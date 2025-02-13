/*
 * ADMC - AD Management Center
 *
 * Copyright (C) 2020-2025 BaseALT Ltd.
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


#include "krb_auth_dialog.h"
#include "ui_krb_auth_dialog.h"

#include "krb5client.h"

KrbAuthDialog::KrbAuthDialog(QWidget *parent) : AuthDialogBase(parent),
    ui(new Ui::KrbAuthDialog) {

    ui->setupUi(this);

    // ...

    setupWidgets();
}

KrbAuthDialog::~KrbAuthDialog() {
    delete ui;
}

void KrbAuthDialog::setupWidgets() {
    ui->error_label->setHidden(true);
    ui->error_label->setStyleSheet("color: red");

    connect(ui->show_passwd_checkbox, &QCheckBox::toggled, this, &KrbAuthDialog::on_show_passwd);
    connect(ui->sign_in_button, &QPushButton::clicked, this, &KrbAuthDialog::on_sign_in);
}

void KrbAuthDialog::on_sign_in() {
    // try {
    client->authenticate(ui->principal_edit->text(), ui->password_edit->text());
    // }
    // catch (...) {}
}

void KrbAuthDialog::on_show_passwd(bool show) {
    show ? ui->password_edit->setEchoMode(QLineEdit::Normal) :
           ui->password_edit->setEchoMode(QLineEdit::Password);
}

void KrbAuthDialog:: show_error_message(const QString &error) {
    ui->error_label->setHidden(false);
    error.isEmpty() ? ui->error_label->setText(tr("Authentication failed")) :
                      ui->error_label->setText(error);
}
