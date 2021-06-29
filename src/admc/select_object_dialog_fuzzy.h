/*
 * ADMC - AD Management Center
 *
 * Copyright (C) 2020-2021 BaseALT Ltd.
 * Copyright (C) 2020-2021 Dmitry Degtyarev
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

#ifndef SELECT_OBJECT_DIALOG_FUZZY_H
#define SELECT_OBJECT_DIALOG_FUZZY_H

#include <QDialog>

class QLineEdit;
class QTreeView;
class QStandardItemModel;
class SelectClassesWidget;
class AdObject;
class SelectBaseWidget;

class SelectObjectDialogFuzzy final : public QDialog {
Q_OBJECT

public:
    SelectObjectDialogFuzzy(const QList<QString> classes, QWidget *parent);

private:
    QStandardItemModel *model;
    QTreeView *view;
    QLineEdit *edit;
    SelectClassesWidget *select_classes;
    SelectBaseWidget *select_base_widget;

    void on_add_button();
};

class SelectFuzzyMatchDialog final : public QDialog {
Q_OBJECT

public:
    SelectFuzzyMatchDialog(const QHash<QString, AdObject> &search_results, QWidget *parent);

    QList<QString> get_selected() const;

private:
    QTreeView *view;
};

#endif /* SELECT_OBJECT_DIALOG_FUZZY_H */
