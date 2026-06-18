#include <gtk/gtk.h>
#include <unistd.h>
#include <stdlib.h>
#include <pwd.h>
#include <errno.h>
#include "scan.h"

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

#define APP_ID    "org.jflc.Envision"
#define APP_TITLE "Envision"

typedef struct {
    GtkWidget   *window;
    GtkWidget   *scan_btn;
    GtkWidget   *pdf_btn;
    GtkWidget   *txt_btn;
    GtkWidget   *progress;
    GtkWidget   *status;
    GtkTreeView *tree;
    GtkListStore *store;
    ScanReport  *report;     /* current report (owned)        */
} App;

enum {
    COL_SEV_LABEL,
    COL_SEV_COLOR,
    COL_CATEGORY,
    COL_TITLE,
    COL_DETAIL,
    COL_SUGGEST,
    COL_FIX,
    N_COLS
};

/* ---- progress plumbing from worker thread ---- */
typedef struct { App *app; char *label; double frac; } ProgMsg;

static gboolean on_progress_main(gpointer data) {
    ProgMsg *m = data;
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
    m->app = ud; m->label = g_strdup(category); m->frac = frac;
    g_idle_add(on_progress_main, m);
}

/* ---- populate the tree from the report (main thread) ---- */
static void populate_tree(App *app) {
    gtk_list_store_clear(app->store);
    ScanReport *r = app->report;
    if (!r) return;
    for (int sev = SEV_CRITICAL; sev >= SEV_OK; sev--) {
        for (guint i = 0; i < r->items->len; i++) {
            Finding *f = g_ptr_array_index(r->items, i);
            if (f->severity != (Severity)sev) continue;
            GtkTreeIter it;
            gtk_list_store_append(app->store, &it);
            gtk_list_store_set(app->store, &it,
                COL_SEV_LABEL, severity_name(f->severity),
                COL_SEV_COLOR, severity_color(f->severity),
                COL_CATEGORY,  f->category,
                COL_TITLE,     f->title,
                COL_DETAIL,    f->detail,
                COL_SUGGEST,   f->suggestion,
                COL_FIX,       f->fix_command ? f->fix_command : "",
                -1);
        }
    }
}

static gboolean on_scan_done(gpointer data) {
    App *app = data;
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
    App *app = data;
    if (app->report) { scan_report_free(app->report); app->report = NULL; }
    app->report = scan_run(progress_cb, app);
    g_idle_add(on_scan_done, app);
    return NULL;
}

static void on_scan_clicked(GtkButton *b, gpointer data) {
    (void)b;
    App *app = data;
    gtk_widget_set_sensitive(app->scan_btn, FALSE);
    gtk_widget_set_sensitive(app->pdf_btn, FALSE);
    gtk_widget_set_sensitive(app->txt_btn, FALSE);
    gtk_label_set_text(GTK_LABEL(app->status), "Scanning system…");
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(app->progress), 0.0);
    GThread *t = g_thread_new("envision-scan", scan_thread, app);
    g_thread_unref(t);
}

static void show_error(App *app, const char *msg) {
    GtkWidget *d = gtk_message_dialog_new(GTK_WINDOW(app->window),
        GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, "%s", msg);
    gtk_dialog_run(GTK_DIALOG(d));
    gtk_widget_destroy(d);
}

static char *ask_save_path(App *app, const char *title, const char *suggested) {
    GtkWidget *d = gtk_file_chooser_dialog_new(title, GTK_WINDOW(app->window),
        GTK_FILE_CHOOSER_ACTION_SAVE,
        "_Cancel", GTK_RESPONSE_CANCEL, "_Save", GTK_RESPONSE_ACCEPT, NULL);
    gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(d), TRUE);
    gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(d), report_save_dir());
    gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(d), suggested);
    char *path = NULL;
    if (gtk_dialog_run(GTK_DIALOG(d)) == GTK_RESPONSE_ACCEPT)
        path = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(d));
    gtk_widget_destroy(d);
    return path;
}

static void on_pdf_clicked(GtkButton *b, gpointer data) {
    (void)b;
    App *app = data;
    if (!app->report) return;
    char *path = ask_save_path(app, "Save report as PDF", "envision-report.pdf");
    if (!path) return;
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
        GtkWidget *d = gtk_message_dialog_new(GTK_WINDOW(app->window),
            GTK_DIALOG_MODAL, GTK_MESSAGE_INFO, GTK_BUTTONS_OK, "%s", m);
        gtk_dialog_run(GTK_DIALOG(d)); gtk_widget_destroy(d);
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

static void on_txt_clicked(GtkButton *b, gpointer data) {
    (void)b;
    App *app = data;
    if (!app->report) return;
    char *path = ask_save_path(app, "Save report as text", "envision-report.txt");
    if (!path) return;
    char *txt = report_to_text(app->report);
    GError *err = NULL;
    if (!g_file_set_contents(path, txt, -1, &err)) {
        show_error(app, err ? err->message : "write failed");
        if (err) g_error_free(err);
    } else {
        chown_to_original_user(path);
    }
    g_free(txt);
    g_free(path);
}

static void on_about_clicked(GtkButton *b, gpointer data) {
    (void)b;
    App *app = data;
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
        "version", "1.0.0",
        "logo-icon-name", "envision",
        "comments", features,
        "copyright", "© 2026 Jean-Francois Lachance-Caumartin",
        "license-type", GTK_LICENSE_MIT_X11,
        "authors", authors,
        NULL);
}

/* Multi-line cell: use the detail column with wrapping. */
static void add_text_col(App *app, const char *title, int col, gboolean wrap) {
    GtkCellRenderer *r = gtk_cell_renderer_text_new();
    if (wrap) {
        g_object_set(r, "wrap-mode", PANGO_WRAP_WORD_CHAR,
                        "wrap-width", 320, NULL);
    }
    GtkTreeViewColumn *c = gtk_tree_view_column_new_with_attributes(
        title, r, "text", col, NULL);
    gtk_tree_view_column_set_resizable(c, TRUE);
    gtk_tree_view_append_column(app->tree, c);
}

static void build_ui(App *app) {
    app->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(app->window), APP_TITLE " — System Security Scanner");
    gtk_window_set_default_size(GTK_WINDOW(app->window), 1100, 680);
    gtk_window_set_icon_name(GTK_WINDOW(app->window), "envision");
    g_signal_connect(app->window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 8);
    gtk_container_add(GTK_CONTAINER(app->window), vbox);

    /* Header bar with title + buttons. */
    GtkWidget *header = gtk_header_bar_new();
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(header), TRUE);
    gtk_header_bar_set_title(GTK_HEADER_BAR(header), APP_TITLE);
    gtk_header_bar_set_subtitle(GTK_HEADER_BAR(header),
        geteuid() == 0 ? "running as root" : "limited (not root)");
    gtk_window_set_titlebar(GTK_WINDOW(app->window), header);

    app->scan_btn = gtk_button_new_with_label("Scan system");
    app->pdf_btn  = gtk_button_new_with_label("Save PDF");
    app->txt_btn  = gtk_button_new_with_label("Save text");
    GtkWidget *about_btn = gtk_button_new_with_label("About");
    gtk_widget_set_sensitive(app->pdf_btn, FALSE);
    gtk_widget_set_sensitive(app->txt_btn, FALSE);
    GtkStyleContext *ctx = gtk_widget_get_style_context(app->scan_btn);
    gtk_style_context_add_class(ctx, "suggested-action");

    gtk_header_bar_pack_start(GTK_HEADER_BAR(header), app->scan_btn);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(header), about_btn);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(header), app->pdf_btn);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(header), app->txt_btn);

    g_signal_connect(app->scan_btn, "clicked", G_CALLBACK(on_scan_clicked), app);
    g_signal_connect(app->pdf_btn,  "clicked", G_CALLBACK(on_pdf_clicked),  app);
    g_signal_connect(app->txt_btn,  "clicked", G_CALLBACK(on_txt_clicked),  app);
    g_signal_connect(about_btn,     "clicked", G_CALLBACK(on_about_clicked), app);

    /* Not-root banner. */
    if (geteuid() != 0) {
        GtkWidget *bar = gtk_info_bar_new();
        gtk_info_bar_set_message_type(GTK_INFO_BAR(bar), GTK_MESSAGE_WARNING);
        GtkWidget *lbl = gtk_label_new(
            "Not running as root — some checks (shadow, full filesystem) will "
            "be limited. Launch via 'pkexec envision' for complete results.");
        gtk_container_add(GTK_CONTAINER(
            gtk_info_bar_get_content_area(GTK_INFO_BAR(bar))), lbl);
        gtk_box_pack_start(GTK_BOX(vbox), bar, FALSE, FALSE, 0);
    }

    /* Results tree. */
    app->store = gtk_list_store_new(N_COLS,
        G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
        G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
    app->tree = GTK_TREE_VIEW(gtk_tree_view_new_with_model(
        GTK_TREE_MODEL(app->store)));
    gtk_tree_view_set_grid_lines(app->tree, GTK_TREE_VIEW_GRID_LINES_HORIZONTAL);

    /* Severity column with colored text. */
    GtkCellRenderer *sr = gtk_cell_renderer_text_new();
    g_object_set(sr, "weight", PANGO_WEIGHT_BOLD, NULL);
    GtkTreeViewColumn *sc = gtk_tree_view_column_new_with_attributes(
        "Severity", sr, "text", COL_SEV_LABEL, "foreground", COL_SEV_COLOR, NULL);
    gtk_tree_view_append_column(app->tree, sc);

    add_text_col(app, "Category",   COL_CATEGORY, FALSE);
    add_text_col(app, "Finding",    COL_TITLE,    TRUE);
    add_text_col(app, "Observed",   COL_DETAIL,   TRUE);
    add_text_col(app, "Advice",     COL_SUGGEST,  TRUE);
    add_text_col(app, "Fix command",COL_FIX,      TRUE);

    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_vexpand(scroll, TRUE);
    gtk_container_add(GTK_CONTAINER(scroll), GTK_WIDGET(app->tree));
    gtk_box_pack_start(GTK_BOX(vbox), scroll, TRUE, TRUE, 0);

    app->progress = gtk_progress_bar_new();
    gtk_progress_bar_set_show_text(GTK_PROGRESS_BAR(app->progress), TRUE);
    gtk_progress_bar_set_text(GTK_PROGRESS_BAR(app->progress),
                              "Press “Scan system” to begin");
    gtk_box_pack_start(GTK_BOX(vbox), app->progress, FALSE, FALSE, 0);

    app->status = gtk_label_new("Ready.");
    gtk_widget_set_halign(app->status, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(vbox), app->status, FALSE, FALSE, 0);
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
    gtk_init(&argc, &argv);
    App app = {0};
    build_ui(&app);
    gtk_widget_show_all(app.window);
    gtk_main();
    if (app.report) scan_report_free(app.report);
    return 0;
}
