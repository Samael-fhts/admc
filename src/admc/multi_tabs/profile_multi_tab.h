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

#ifndef PROFILE_MULTI_TAB_H
#define PROFILE_MULTI_TAB_H

#include <QWidget>

class AttributeEdit;
class QCheckBox;

namespace Ui {
class ProfileMultiTab;
}

class ProfileMultiTab final : public QWidget {
    Q_OBJECT

public:
    Ui::ProfileMultiTab *ui;

    ProfileMultiTab(QList<AttributeEdit *> *edit_list, QHash<AttributeEdit *, QCheckBox *> *check_map, QWidget *parent);
    ~ProfileMultiTab();
};

#endif /* PROFILE_MULTI_TAB_H */
