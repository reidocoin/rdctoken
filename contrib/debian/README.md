
Debian
====================
This directory contains files used to package rdctd/rdct-qt
for Debian-based Linux systems. If you compile rdctd/rdct-qt yourself, there are some useful files here.

## rdct: URI support ##


rdct-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install rdct-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your rdctqt binary to `/usr/bin`
and the `../../share/pixmaps/rdct128.png` to `/usr/share/pixmaps`

rdct-qt.protocol (KDE)

