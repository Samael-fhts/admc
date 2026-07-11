/*
 * ADMC - AD Management Center
 *
 * Copyright (C) 2020-2025 BaseALT Ltd.
 * Copyright (C) 2020-2025 Dmitry Degtyarev
 * Copyright (C) 2026 Artyom V. Poptsov
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "changelog_dialog.h"
#include "ui_changelog_dialog.h"

#include "config.h"
#include "settings.h"

#include <QCoreApplication>
#include <QDebug>
#include <QStandardPaths>
#include <QFile>

/**
 * Read a change log file and return its contents.
 *
 * @return The change log file contents or an error message on errors.
 */
QString ChangelogDialog::read_changelog() const {
    const QString fail_text = tr("Failed to open changelog file.");
    const QLocale saved_locale =
        settings_get_variant(SETTING_locale).toLocale();

    QString changelog_file_name;
    if (saved_locale.language() == QLocale::Russian) {
        changelog_file_name = "CHANGELOG_ru.txt";
    } else {
        changelog_file_name = "CHANGELOG.txt";
    }

#ifdef QT_DEBUG
    QString changelog_path =
        QString("%1/%2").arg(QCoreApplication::applicationDirPath(),
                             changelog_file_name);
#else
    QString changelog_path =
        QStandardPaths::locate(
            QStandardPaths::GenericDataLocation,
            QString("doc/admc-%1/%2").arg(ADMC_VERSION,
                                          changelog_file_name));
#endif

    if (changelog_path.isEmpty()) {
        return fail_text;
    }

    QFile file(changelog_path);

    const bool open_success = file.open(QIODevice::ReadOnly);
    if (!open_success) {
        qDebug() << "Failed to open changelog file";

        return fail_text;
    }

    QString changelog_text = file.readAll();

    file.close();

    // Remove forced word wrap contained in
    // CHANGELOG.txt so that resizing the dialog
    // expands text width (all wrapped lines start
    // with 2 spaces)
    changelog_text.replace("\n  ", " ");

    return changelog_text;
}

ChangelogDialog::ChangelogDialog(QWidget *parent)
: QDialog(parent) {
    ui = new Ui::ChangelogDialog();
    ui->setupUi(this);

    setAttribute(Qt::WA_DeleteOnClose);

    QString changelog_text = read_changelog();
    ui->edit->setPlainText(changelog_text);
    settings_setup_dialog_geometry(SETTING_changelog_dialog_geometry, this);
}

ChangelogDialog::~ChangelogDialog() {
    delete ui;
}
