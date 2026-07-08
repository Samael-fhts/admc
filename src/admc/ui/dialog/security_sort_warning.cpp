/*
 * ADMC - AD Management Center
 *
 * Copyright (C) 2020-2026 BaseALT Ltd.
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

#include "ui/dialog/security_sort_warning.h"
#include "ui/dialog/ui_security_sort_warning.h"

SecuritySortWarningDialog::SecuritySortWarningDialog(QWidget *parent)
: QDialog(parent) {
    ui = new Ui::SecuritySortWarningDialog();
    ui->setupUi(this);

    setAttribute(Qt::WA_DeleteOnClose);

    fix_order_button = new QPushButton();
    cancel_button = new QPushButton();
    ui->button_box->addButton(fix_order_button, QDialogButtonBox::AcceptRole);
    ui->button_box->addButton(cancel_button, QDialogButtonBox::RejectRole);
    retranslate_ui();
}

SecuritySortWarningDialog::~SecuritySortWarningDialog() {
    delete ui;
}

void SecuritySortWarningDialog::retranslate_ui() {
    ui->label->setText(
        tr("This object's security descriptor contains ACL that has incorrect order. Fix order to proceed with editing. If order is not fixed, Security tab will be read only."));
    fix_order_button->setText(tr("Fix order"));
    cancel_button->setText(tr("Cancel"));
}

bool SecuritySortWarningDialog::event(QEvent *event) {
    if (event->type() == QEvent::LanguageChange) {
        ui->retranslateUi(this);
        retranslate_ui();
    }
    return QDialog::event(event);
}
