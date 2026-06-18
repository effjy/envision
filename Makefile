# Envision — Makefile
# Builds the GTK3 binary and installs it together with its icon, desktop
# entry, polkit policy and launcher so it appears in the application menu
# and the window/taskbar.

PROG       := envision
PREFIX     ?= /usr
BINDIR     := $(DESTDIR)$(PREFIX)/bin
DATADIR    := $(DESTDIR)$(PREFIX)/share
APPDIR     := $(DATADIR)/applications
POLKITDIR  := $(DATADIR)/polkit-1/actions
ICONBASE   := $(DATADIR)/icons/hicolor
ICON_SIZES := 16 22 24 32 48 64 128 256

CC         ?= cc
PKG        := gtk+-3.0
CFLAGS     ?= -O2 -Wall -Wextra
CFLAGS     += $(shell pkg-config --cflags $(PKG))
LDLIBS     := $(shell pkg-config --libs $(PKG)) -lpthread

SRC        := $(wildcard src/*.c)
OBJ        := $(SRC:.c=.o)

# Tools used to rasterize the SVG icon (first one found wins).
RSVG       := $(shell command -v rsvg-convert 2>/dev/null)
INKSCAPE   := $(shell command -v inkscape 2>/dev/null)
CONVERT    := $(shell command -v convert 2>/dev/null)

.PHONY: all clean install uninstall icons run

all: $(PROG)

$(PROG): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDLIBS)

src/%.o: src/%.c src/scan.h
	$(CC) $(CFLAGS) -c $< -o $@

run: $(PROG)
	./$(PROG)

# ---- PNG icon generation from the SVG (best effort) ----
icons: $(addprefix icons/envision-,$(addsuffix .png,$(ICON_SIZES)))

icons/envision-%.png: icons/envision.svg
	@echo "  ICON   $@ ($*x$*)"
	@if [ -n "$(RSVG)" ]; then \
		$(RSVG) -w $* -h $* $< -o $@; \
	elif [ -n "$(INKSCAPE)" ]; then \
		$(INKSCAPE) $< -w $* -h $* -o $@ >/dev/null 2>&1; \
	elif [ -n "$(CONVERT)" ]; then \
		$(CONVERT) -background none -resize $*x$* $< $@; \
	else \
		echo "  (no rsvg-convert/inkscape/convert — SVG icon will be installed instead)"; \
	fi

# ---- install ----
install: all icons
	# Binary
	install -Dm755 $(PROG) $(BINDIR)/$(PROG)
	# Launcher wrapper (pkexec + display env)
	install -Dm755 desktop/envision-launcher $(BINDIR)/envision-launcher
	# Desktop entry -> shows in the application menu
	install -Dm644 desktop/envision.desktop $(APPDIR)/envision.desktop
	# Polkit policy -> lets pkexec run it with a GUI auth prompt
	install -Dm644 polkit/org.jflc.Envision.policy \
		$(POLKITDIR)/org.jflc.Envision.policy
	# Scalable SVG icon (always installed as a fallback / HiDPI source)
	install -Dm644 icons/envision.svg \
		$(ICONBASE)/scalable/apps/envision.svg
	# Rasterized PNG icons at each size -> window/taskbar icon
	@for s in $(ICON_SIZES); do \
		if [ -f icons/envision-$$s.png ]; then \
			install -Dm644 icons/envision-$$s.png \
				$(ICONBASE)/$${s}x$${s}/apps/envision.png; \
			echo "  install icon $${s}x$${s}"; \
		fi; \
	done
	# Refresh caches so the icon and menu entry appear immediately
	-gtk-update-icon-cache -f -t $(ICONBASE) 2>/dev/null || true
	-update-desktop-database $(APPDIR) 2>/dev/null || true
	@echo ""
	@echo "Envision installed. Launch it from the application menu, or run:"
	@echo "    envision-launcher"

uninstall:
	rm -f $(BINDIR)/$(PROG)
	rm -f $(BINDIR)/envision-launcher
	rm -f $(APPDIR)/envision.desktop
	rm -f $(POLKITDIR)/org.jflc.Envision.policy
	rm -f $(ICONBASE)/scalable/apps/envision.svg
	@for s in $(ICON_SIZES); do \
		rm -f $(ICONBASE)/$${s}x$${s}/apps/envision.png; \
	done
	-gtk-update-icon-cache -f -t $(ICONBASE) 2>/dev/null || true
	-update-desktop-database $(APPDIR) 2>/dev/null || true
	@echo "Envision uninstalled."

clean:
	rm -f $(OBJ) $(PROG) icons/envision-*.png
