#include <gtk/gtk.h>
#include <unistd.h>
#include <stdlib.h>
#include <pwd.h>
#include <errno.h>
#include "scan.hpp"

/* Where to default the "Save report" dialog. When elevated via pkexec/sudo the
 * process runs as root (HOME=/root), but the user expects the report in their
 * own home. Resolve, in order of preference:
 *   1. ENVISION_ORIG_HOME  — forwarded by envision-launcher
 *   2. PKEXEC_UID          — set by pkexec; look up that user's home
 *   3. SUDO_USER           — set by sudo
 *   4. the current HOME    — normal unprivileged run
 */
static const char *report_save_dir(void) {
    const char *h = g_getenv("ENVISION_ORIG_HOME");
    if (h && *h && g_file_test(h, G_FILE_TEST_IS_DIR)) return h;

    const char *uid_s = g_getenv("PKEXEC_UID");
    if (uid_s && *uid_s) {
        struct passwd *pw = getpwuid((uid_t)atoi(uid_s));
        if (pw && pw->pw_dir && g_file_test(pw->pw_dir, G_FILE_TEST_IS_DIR))
            return pw->pw_dir;
    }
    const char *su = g_getenv("SUDO_USER");
    if (su && *su) {
        struct passwd *pw = getpwnam(su);
        if (pw && pw->pw_dir && g_file_test(pw->pw_dir, G_FILE_TEST_IS_DIR))
            return pw->pw_dir;
    }
    return g_get_home_dir();
}

/* When running as root on behalf of a normal user, hand ownership of a saved
 * report back to that user so they can manage it without sudo. No-op if we are
 * not root or cannot determine the original user. */
static void chown_to_original_user(const char *path) {
    if (geteuid() != 0) return;
    struct passwd *pw = NULL;
    const char *uid_s = g_getenv("PKEXEC_UID");
    if (uid_s && *uid_s) pw = getpwuid((uid_t)atoi(uid_s));
    if (!pw) {
        const char *user = g_getenv("ENVISION_ORIG_USER");
        if (user && *user) pw = getpwnam(user);
    }
    if (!pw) {
        const char *su = g_getenv("SUDO_USER");
        if (su && *su) pw = getpwnam(su);
    }
    if (pw) {
        if (chown(path, pw->pw_uid, pw->pw_gid) != 0)
            g_warning("Could not chown report to original user: %s",
                      g_strerror(errno));
    }
}

#define APP_ID      "org.jflc.Envision"
#define APP_TITLE   "Envision"
#define APP_VERSION "1.0.1"

/* ------------------------------------------------------------------ */
/* EnvFinding: a GObject wrapping one finding's display strings, used as
 * the item type for the GtkColumnView's GListStore model.              */
/* ------------------------------------------------------------------ */

#define ENV_TYPE_FINDING (env_finding_get_type())
G_DECLARE_FINAL_TYPE(EnvFinding, env_finding, ENV, FINDING, GObject)

struct _EnvFinding {
    GObject parent_instance;
    char *sev_label;
    char *sev_color;
    char *category;
    char *title;
    char *detail;
    char *suggest;
    char *fix;
};

G_DEFINE_FINAL_TYPE(EnvFinding, env_finding, G_TYPE_OBJECT)

static void env_finding_finalize(GObject *o) {
    EnvFinding *f = ENV_FINDING(o);
    g_free(f->sev_label);
    g_free(f->sev_color);
    g_free(f->category);
    g_free(f->title);
    g_free(f->detail);
    g_free(f->suggest);
    g_free(f->fix);
    G_OBJECT_CLASS(env_finding_parent_class)->finalize(o);
}

static void env_finding_class_init(EnvFindingClass *klass) {
    G_OBJECT_CLASS(klass)->finalize = env_finding_finalize;
}

static void env_finding_init(EnvFinding *) {}

static EnvFinding *env_finding_new(const Finding *src) {
    EnvFinding *f = ENV_FINDING(g_object_new(ENV_TYPE_FINDING, NULL));
    f->sev_label = g_strdup(severity_name(src->severity));
    f->sev_color = g_strdup(severity_color(src->severity));
    f->category  = g_strdup(src->category);
    f->title     = g_strdup(src->title);
    f->detail    = g_strdup(src->detail);
    f->suggest   = g_strdup(src->suggestion);
    f->fix       = g_strdup(src->fix_command ? src->fix_command : "");
    return f;
}

/* Logical columns, used to pick which field a factory renders. */
enum {
    F_SEVERITY,
    F_CATEGORY,
    F_TITLE,
    F_DETAIL,
    F_SUGGEST,
    F_FIX
};

struct App {
    GtkApplication *gapp;
    GtkWidget   *window;
    GtkWidget   *scan_btn;
    GtkWidget   *pdf_btn;
    GtkWidget   *txt_btn;
    GtkWidget   *progress;
    GtkWidget   *status;
    GListStore  *store;      /* model of EnvFinding* for the column view */
    ScanReport  *report;     /* current report (owned)        */
};

/* ---- progress plumbing from worker thread ---- */
struct ProgMsg { App *app; char *label; double frac; };

static gboolean on_progress_main(gpointer data) {
    ProgMsg *m = static_cast<ProgMsg *>(data);
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(m->app->progress), m->frac);
    char *txt = g_strdup_printf("Scanning: %s", m->label);
    gtk_progress_bar_set_text(GTK_PROGRESS_BAR(m->app->progress), txt);
    g_free(txt);
    g_free(m->label);
    g_free(m);
    return G_SOURCE_REMOVE;
}

static void progress_cb(const char *category, double frac, gpointer ud) {
    ProgMsg *m = g_new0(ProgMsg, 1);
    m->app = static_cast<App *>(ud); m->label = g_strdup(category); m->frac = frac;
    g_idle_add(on_progress_main, m);
}

/* ---- populate the model from the report (main thread) ---- */
static void populate_tree(App *app) {
    g_list_store_remove_all(app->store);
    ScanReport *r = app->report;
    if (!r) return;
    for (int sev = SEV_CRITICAL; sev >= SEV_OK; sev--) {
        for (guint i = 0; i < r->items->len; i++) {
            Finding *f = static_cast<Finding *>(g_ptr_array_index(r->items, i));
            if (f->severity != (Severity)sev) continue;
            EnvFinding *item = env_finding_new(f);
            g_list_store_append(app->store, item);
            g_object_unref(item);   /* the store holds the only ref now */
        }
    }
}

static gboolean on_scan_done(gpointer data) {
    App *app = static_cast<App *>(data);
    populate_tree(app);
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(app->progress), 1.0);
    gtk_progress_bar_set_text(GTK_PROGRESS_BAR(app->progress), "Scan complete");
    char sum[256];
    ScanReport *r = app->report;
    g_snprintf(sum, sizeof sum,
               "Done — Critical: %d, High: %d, Medium: %d, Low: %d, OK: %d",
               r->counts[SEV_CRITICAL], r->counts[SEV_HIGH],
               r->counts[SEV_MEDIUM], r->counts[SEV_LOW], r->counts[SEV_OK]);
    gtk_label_set_text(GTK_LABEL(app->status), sum);
    gtk_widget_set_sensitive(app->scan_btn, TRUE);
    gtk_widget_set_sensitive(app->pdf_btn, TRUE);
    gtk_widget_set_sensitive(app->txt_btn, TRUE);
    return G_SOURCE_REMOVE;
}

static gpointer scan_thread(gpointer data) {
    App *app = static_cast<App *>(data);
    if (app->report) { scan_report_free(app->report); app->report = NULL; }
    app->report = scan_run(progress_cb, app);
    g_idle_add(on_scan_done, app);
    return NULL;
}

static void on_scan_clicked(GtkButton *b, gpointer data) {
    (void)b;
    App *app = static_cast<App *>(data);
    gtk_widget_set_sensitive(app->scan_btn, FALSE);
    gtk_widget_set_sensitive(app->pdf_btn, FALSE);
    gtk_widget_set_sensitive(app->txt_btn, FALSE);
    gtk_label_set_text(GTK_LABEL(app->status), "Scanning system…");
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(app->progress), 0.0);
    GThread *t = g_thread_new("envision-scan", scan_thread, app);
    g_thread_unref(t);
}

/* ---- modal message via GtkAlertDialog (fire-and-forget) ---- */
static void show_message(App *app, const char *msg) {
    GtkAlertDialog *d = gtk_alert_dialog_new("%s", msg);
    gtk_alert_dialog_show(d, GTK_WINDOW(app->window));
    g_object_unref(d);
}

static void show_error(App *app, const char *msg) {
    show_message(app, msg);
}

/* ---- async "save report" via GtkFileDialog ---- */
static void do_save_pdf(App *app, const char *in_path) {
    char *path = g_strdup(in_path);
    if (!g_str_has_suffix(path, ".pdf")) {
        char *p2 = g_strconcat(path, ".pdf", NULL); g_free(path); path = p2;
    }
    char *tex = report_to_latex(app->report);
    char *err = NULL;
    gboolean ok = report_write_pdf(tex, path, &err);
    g_free(tex);
    if (ok) {
        chown_to_original_user(path);
        char *m = g_strdup_printf("PDF saved to:\n%s", path);
        show_message(app, m);
        g_free(m);
    } else {
        char *m = g_strdup_printf("Could not create PDF.\n%s",
                                  err ? err : "Unknown error");
        show_error(app, m);
        g_free(m);
    }
    g_free(err);
    g_free(path);
}

static void do_save_txt(App *app, const char *path) {
    char *txt = report_to_text(app->report);
    GError *err = NULL;
    if (!g_file_set_contents(path, txt, -1, &err)) {
        show_error(app, err ? err->message : "write failed");
        if (err) g_error_free(err);
    } else {
        chown_to_original_user(path);
    }
    g_free(txt);
}

static void on_save_pdf_ready(GObject *source, GAsyncResult *res,
                              gpointer data) {
    App *app = static_cast<App *>(data);
    GError *err = NULL;
    GFile *f = gtk_file_dialog_save_finish(GTK_FILE_DIALOG(source), res, &err);
    if (f) {
        char *path = g_file_get_path(f);
        g_object_unref(f);
        if (path) { do_save_pdf(app, path); g_free(path); }
    } else if (err) {
        g_error_free(err);   /* user cancelled or dismissed: nothing to do */
    }
}

static void on_save_txt_ready(GObject *source, GAsyncResult *res,
                              gpointer data) {
    App *app = static_cast<App *>(data);
    GError *err = NULL;
    GFile *f = gtk_file_dialog_save_finish(GTK_FILE_DIALOG(source), res, &err);
    if (f) {
        char *path = g_file_get_path(f);
        g_object_unref(f);
        if (path) { do_save_txt(app, path); g_free(path); }
    } else if (err) {
        g_error_free(err);
    }
}

static GtkFileDialog *make_save_dialog(const char *title, const char *suggested) {
    GtkFileDialog *d = gtk_file_dialog_new();
    gtk_file_dialog_set_title(d, title);
    gtk_file_dialog_set_initial_name(d, suggested);
    GFile *folder = g_file_new_for_path(report_save_dir());
    gtk_file_dialog_set_initial_folder(d, folder);
    g_object_unref(folder);
    return d;
}

static void on_pdf_clicked(GtkButton *b, gpointer data) {
    (void)b;
    App *app = static_cast<App *>(data);
    if (!app->report) return;
    GtkFileDialog *d = make_save_dialog("Save report as PDF",
                                        "envision-report.pdf");
    gtk_file_dialog_save(d, GTK_WINDOW(app->window), NULL,
                         on_save_pdf_ready, app);
    g_object_unref(d);
}

static void on_txt_clicked(GtkButton *b, gpointer data) {
    (void)b;
    App *app = static_cast<App *>(data);
    if (!app->report) return;
    GtkFileDialog *d = make_save_dialog("Save report as text",
                                        "envision-report.txt");
    gtk_file_dialog_save(d, GTK_WINDOW(app->window), NULL,
                         on_save_txt_ready, app);
    g_object_unref(d);
}

static void on_about_clicked(GtkButton *b, gpointer data) {
    (void)b;
    App *app = static_cast<App *>(data);
    const char *authors[] = { "Jean-Francois Lachance-Caumartin", NULL };
    const char *features =
        "Envision performs a security-posture scan of your Linux system and "
        "produces an actionable hardening report.\n\n"
        "Features:\n"
        "• Pending & automatic security update checks\n"
        "• Host firewall status (ufw / firewalld)\n"
        "• Listening sockets — flags services bound to public interfaces\n"
        "• SSH server hardening (root login, password auth)\n"
        "• Passwordless sudo (NOPASSWD) detection\n"
        "• Account audit (UID 0 duplicates, empty passwords)\n"
        "• World-writable system files & SUID inventory\n"
        "• Kernel hardening sysctls (ASLR, rp_filter, syncookies, …)\n"
        "• Disk-encryption and core-dump checks\n"
        "• Failed systemd unit review\n"
        "• Each finding includes a severity, an explanation, and a "
        "copy-paste fix command\n"
        "• Export the report to PDF (via pdflatex) or plain text\n\n"
        "Run as root via pkexec for complete results.";
    gtk_show_about_dialog(GTK_WINDOW(app->window),
        "program-name", APP_TITLE,
        "version", APP_VERSION,
        "logo-icon-name", "envision",
        "comments", features,
        "copyright", "© 2026 Jean-Francois Lachance-Caumartin",
        "license-type", GTK_LICENSE_MIT_X11,
        "authors", authors,
        NULL);
}

/* ---- GtkColumnView factory callbacks ----
 * Each column shares these two callbacks; the field index is passed as the
 * factory's user_data and the wrap flag is stashed on the label widget. */
static void col_setup(GtkSignalListItemFactory *, GtkListItem *item,
                      gpointer wrap_flag) {
    GtkWidget *lbl = gtk_label_new(NULL);
    gtk_label_set_xalign(GTK_LABEL(lbl), 0.0);
    gtk_widget_set_valign(lbl, GTK_ALIGN_START);
    if (GPOINTER_TO_INT(wrap_flag)) {
        gtk_label_set_wrap(GTK_LABEL(lbl), TRUE);
        gtk_label_set_wrap_mode(GTK_LABEL(lbl), PANGO_WRAP_WORD_CHAR);
        gtk_label_set_max_width_chars(GTK_LABEL(lbl), 44);
    }
    gtk_list_item_set_child(item, lbl);
}

static void col_bind(GtkSignalListItemFactory *, GtkListItem *item,
                     gpointer field_id) {
    EnvFinding *f = ENV_FINDING(gtk_list_item_get_item(item));
    GtkLabel *lbl = GTK_LABEL(gtk_list_item_get_child(item));
    switch (GPOINTER_TO_INT(field_id)) {
        case F_SEVERITY: {
            /* Bold, severity-coloured text via Pango markup. */
            char *m = g_markup_printf_escaped(
                "<span foreground='%s' weight='bold'>%s</span>",
                f->sev_color, f->sev_label);
            gtk_label_set_markup(lbl, m);
            g_free(m);
            break;
        }
        case F_CATEGORY: gtk_label_set_text(lbl, f->category); break;
        case F_TITLE:    gtk_label_set_text(lbl, f->title);    break;
        case F_DETAIL:   gtk_label_set_text(lbl, f->detail);   break;
        case F_SUGGEST:  gtk_label_set_text(lbl, f->suggest);  break;
        case F_FIX:      gtk_label_set_text(lbl, f->fix);      break;
    }
}

static void add_column(GtkColumnView *view, const char *title, int field,
                       gboolean wrap) {
    GtkListItemFactory *factory = gtk_signal_list_item_factory_new();
    g_signal_connect(factory, "setup", G_CALLBACK(col_setup),
                     GINT_TO_POINTER(wrap));
    g_signal_connect(factory, "bind", G_CALLBACK(col_bind),
                     GINT_TO_POINTER(field));
    GtkColumnViewColumn *c = gtk_column_view_column_new(title, factory);
    gtk_column_view_column_set_resizable(c, TRUE);
    if (wrap) gtk_column_view_column_set_expand(c, TRUE);
    gtk_column_view_append_column(view, c);
    g_object_unref(c);
}

static void build_ui(App *app) {
    app->window = gtk_application_window_new(app->gapp);
    gtk_window_set_title(GTK_WINDOW(app->window),
                         APP_TITLE " — System Security Scanner");
    /* Bind the window to its themed icon so it shows up in the window list /
     * taskbar. Without this GTK has no icon to advertise (the .desktop entry
     * alone is not enough, especially when running elevated via pkexec). */
    gtk_window_set_icon_name(GTK_WINDOW(app->window), "envision");
    gtk_window_set_default_size(GTK_WINDOW(app->window), 1100, 680);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_widget_set_margin_top(vbox, 8);
    gtk_widget_set_margin_bottom(vbox, 8);
    gtk_widget_set_margin_start(vbox, 8);
    gtk_widget_set_margin_end(vbox, 8);
    gtk_window_set_child(GTK_WINDOW(app->window), vbox);

    /* Header bar with title + buttons. */
    GtkWidget *header = gtk_header_bar_new();
    gtk_header_bar_set_show_title_buttons(GTK_HEADER_BAR(header), TRUE);
    GtkWidget *title_lbl = gtk_label_new(
        geteuid() == 0 ? APP_TITLE " — running as root"
                       : APP_TITLE " — limited (not root)");
    gtk_widget_add_css_class(title_lbl, "title");
    gtk_header_bar_set_title_widget(GTK_HEADER_BAR(header), title_lbl);
    gtk_window_set_titlebar(GTK_WINDOW(app->window), header);

    app->scan_btn = gtk_button_new_with_label("Scan system");
    app->pdf_btn  = gtk_button_new_with_label("Save PDF");
    app->txt_btn  = gtk_button_new_with_label("Save text");
    GtkWidget *about_btn = gtk_button_new_with_label("About");
    gtk_widget_set_sensitive(app->pdf_btn, FALSE);
    gtk_widget_set_sensitive(app->txt_btn, FALSE);
    gtk_widget_add_css_class(app->scan_btn, "suggested-action");

    gtk_header_bar_pack_start(GTK_HEADER_BAR(header), app->scan_btn);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(header), about_btn);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(header), app->pdf_btn);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(header), app->txt_btn);

    g_signal_connect(app->scan_btn, "clicked", G_CALLBACK(on_scan_clicked), app);
    g_signal_connect(app->pdf_btn,  "clicked", G_CALLBACK(on_pdf_clicked),  app);
    g_signal_connect(app->txt_btn,  "clicked", G_CALLBACK(on_txt_clicked),  app);
    g_signal_connect(about_btn,     "clicked", G_CALLBACK(on_about_clicked), app);

    /* Not-root banner: a simple styled box (GtkInfoBar is deprecated). */
    if (geteuid() != 0) {
        GtkWidget *bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        gtk_widget_add_css_class(bar, "card");
        gtk_widget_set_margin_top(bar, 2);
        gtk_widget_set_margin_bottom(bar, 2);
        GtkWidget *icon = gtk_image_new_from_icon_name("dialog-warning-symbolic");
        gtk_widget_set_margin_start(icon, 8);
        GtkWidget *lbl = gtk_label_new(
            "Not running as root — some checks (shadow, full filesystem) will "
            "be limited. Launch via 'pkexec envision' for complete results.");
        gtk_label_set_wrap(GTK_LABEL(lbl), TRUE);
        gtk_label_set_xalign(GTK_LABEL(lbl), 0.0);
        gtk_widget_set_hexpand(lbl, TRUE);
        gtk_widget_set_margin_top(lbl, 6);
        gtk_widget_set_margin_bottom(lbl, 6);
        gtk_widget_set_margin_end(lbl, 8);
        gtk_box_append(GTK_BOX(bar), icon);
        gtk_box_append(GTK_BOX(bar), lbl);
        gtk_box_append(GTK_BOX(vbox), bar);
    }

    /* Results table — modern GtkColumnView backed by a GListStore. */
    app->store = g_list_store_new(ENV_TYPE_FINDING);
    GtkNoSelection *sel = gtk_no_selection_new(G_LIST_MODEL(app->store));
    GtkWidget *colview = gtk_column_view_new(GTK_SELECTION_MODEL(sel));
    gtk_column_view_set_show_row_separators(GTK_COLUMN_VIEW(colview), TRUE);
    gtk_column_view_set_show_column_separators(GTK_COLUMN_VIEW(colview), TRUE);

    GtkColumnView *cv = GTK_COLUMN_VIEW(colview);
    add_column(cv, "Severity",    F_SEVERITY, FALSE);
    add_column(cv, "Category",    F_CATEGORY, FALSE);
    add_column(cv, "Finding",     F_TITLE,    TRUE);
    add_column(cv, "Observed",    F_DETAIL,   TRUE);
    add_column(cv, "Advice",      F_SUGGEST,  TRUE);
    add_column(cv, "Fix command", F_FIX,      TRUE);

    GtkWidget *scroll = gtk_scrolled_window_new();
    gtk_widget_set_vexpand(scroll, TRUE);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), colview);
    gtk_box_append(GTK_BOX(vbox), scroll);

    app->progress = gtk_progress_bar_new();
    gtk_progress_bar_set_show_text(GTK_PROGRESS_BAR(app->progress), TRUE);
    gtk_progress_bar_set_text(GTK_PROGRESS_BAR(app->progress),
                              "Press “Scan system” to begin");
    gtk_box_append(GTK_BOX(vbox), app->progress);

    app->status = gtk_label_new("Ready.");
    gtk_widget_set_halign(app->status, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(vbox), app->status);
}

static void on_activate(GtkApplication *gapp, gpointer data) {
    App *app = static_cast<App *>(data);
    if (app->window) {     /* second activation: just present it */
        gtk_window_present(GTK_WINDOW(app->window));
        return;
    }
    app->gapp = gapp;
    build_ui(app);
    gtk_window_present(GTK_WINDOW(app->window));
}

/* Headless mode: `envision --cli [report.pdf]` runs the scan, prints the
 * text report to stdout, and optionally writes a PDF. No display required. */
static int run_cli(int argc, char **argv) {
    ScanReport *r = scan_run(NULL, NULL);
    char *txt = report_to_text(r);
    fputs(txt, stdout);
    g_free(txt);
    int rc = 0;
    if (argc >= 3) {
        char *tex = report_to_latex(r);
        char *err = NULL;
        if (report_write_pdf(tex, argv[2], &err)) {
            chown_to_original_user(argv[2]);
            g_print("\nPDF written to %s\n", argv[2]);
        } else {
            g_printerr("\nPDF failed: %s\n", err ? err : "unknown");
            rc = 1;
        }
        g_free(tex); g_free(err);
    }
    scan_report_free(r);
    return rc;
}

int main(int argc, char **argv) {
    if (argc >= 2 && g_str_equal(argv[1], "--cli"))
        return run_cli(argc, argv);
    if (argc >= 2 && (g_str_equal(argv[1], "--help") || g_str_equal(argv[1], "-h"))) {
        g_print("Envision — system security scanner\n"
                "Usage:\n"
                "  envision              launch the GTK interface\n"
                "  envision --cli [out.pdf]   run headless, print report, "
                "optionally write PDF\n"
                "Run as root (pkexec) for complete results.\n");
        return 0;
    }

    App app = {};
    /* G_APPLICATION_NON_UNIQUE: a root instance and a user instance may both
     * run; don't try to be the single owner of the bus name. */
    app.gapp = gtk_application_new(APP_ID, G_APPLICATION_NON_UNIQUE);
    g_signal_connect(app.gapp, "activate", G_CALLBACK(on_activate), &app);
    int status = g_application_run(G_APPLICATION(app.gapp), 1, argv);
    if (app.report) scan_report_free(app.report);
    g_object_unref(app.gapp);
    return status;
}
