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

#ifndef GENERAL_POLICY_TAB_H
#define GENERAL_POLICY_TAB_H

#include <QWidget>
#include "attribute_edits/attribute_edit.h"

class AdObject;
class GeneralPolicyTabEdit;
class AttributeEdit;

namespace Ui {
class GeneralPolicyTab;
}

class GeneralPolicyTab final : public QWidget {
    Q_OBJECT

public:
    Ui::GeneralPolicyTab *ui;

    GeneralPolicyTab(QList<AttributeEdit *> *edit_list, QWidget *parent);
    ~GeneralPolicyTab();
};

class GeneralPolicyTabEdit final : public AttributeEdit {
    Q_OBJECT

public:
    GeneralPolicyTabEdit(Ui::GeneralPolicyTab *ui, QObject *parent);

    void load(AdInterface &ad, const AdObject &object) override;

private:
    Ui::GeneralPolicyTab *ui;
};

#endif /* GENERAL_POLICY_TAB_H */
