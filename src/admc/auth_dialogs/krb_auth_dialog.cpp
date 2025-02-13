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

#include <stdexcept>
#include "settings.h"


KrbAuthDialog::KrbAuthDialog(QWidget *parent) : AuthDialogBase(parent),
    ui(new Ui::KrbAuthDialog) {

    ui->setupUi(this);

    setupWidgets();

    try {
        client = std::unique_ptr<Krb5Client>(new Krb5Client);
    }
    catch (const std::runtime_error& e) {
        show_error_message(e.what());
    }
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
    try {
        client->authenticate(ui->principal_edit->text(), ui->password_edit->text());
    }
    catch (const std::runtime_error& e) {
        show_error_message(e.what());
    }
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

void KrbAuthDialog::on_use_default_cache(bool checked) {
    ui->principal_edit->setDisabled(checked);
    ui->password_edit->setHidden(checked);
    settings_set_variant(SETTING_use_default_credentials, checked);

    if (checked) {
        const QString default_principal = client->default_principal();
        if (default_principal.isEmpty()) {
            show_error_message(tr("Failed to find default credential cache"));
            ui->sign_in_button->setDisabled(true);
            ui->principal_edit->clear();
            return;
        }
        ui->sign_in_button->setDisabled(false);
        ui->principal_edit->setText(default_principal);
    } else {
        ui->sign_in_button->setDisabled(false);
        ui->error_label->setHidden(true);
        ui->principal_edit->setText(client->current_principal());
    }
}
