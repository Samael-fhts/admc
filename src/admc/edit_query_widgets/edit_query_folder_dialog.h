/*
 * ADMC - AD Management Center
 *
 * Copyright (C) 2020-2025 BaseALT Ltd.
 * Copyright (C) 2020-2025 Dmitry Degtyarev
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

#ifndef EDIT_QUERY_FOLDER_DIALOG_H
#define EDIT_QUERY_FOLDER_DIALOG_H

#include <QDialog>

namespace Ui {
class EditQueryFolderDialog;
}

class EditQueryFolderDialog : public QDialog {
    Q_OBJECT

public:
    Ui::EditQueryFolderDialog *ui;

    EditQueryFolderDialog(QWidget *parent);
    ~EditQueryFolderDialog();

    QString name() const;
    QString description() const;

    void set_data(const QList<QString> &sibling_name_list, const QString &name, const QString &description);
    void accept() override;

private:
    QList<QString> sibling_name_list;
};

#endif /* EDIT_QUERY_FOLDER_DIALOG_H */
