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

#include "krb5client.h"

#include <stdexcept>
#include <QCoreApplication>


Krb5Client::Krb5Client() : context(NULL), ccache(NULL), principal(NULL) {
    krb5_error_code result;
    QString error;

    result = krb5_init_context(&context);
    if (result) {
        error = QCoreApplication::translate("Krb5Client", "Kerberos initialization failed");
        throw(std::runtime_error(error.toUtf8().data()));
    }

    result = krb5_cc_default(context, &ccache);
    if (result) {
        state = Krb5TgtState_Empty;
        error = QCoreApplication::translate("Krb5Client", "Failed to get credential cache");
        throw(std::runtime_error(error.toUtf8().data()));
    }

    result = krb5_cc_get_principal(context, ccache, principal);
    if (result) {
        state = Krb5TgtState_Invalid;
        error = QCoreApplication::translate("Krb5Client", "Failed to get principal from credential cache");
        throw(std::runtime_error(error.toUtf8().data()));
    }

    memset(&creds, 0, sizeof(creds));
    result = krb5_build_principal(context, &creds.server,
                                   krb5_princ_realm(context, principal)->length,
                                   krb5_princ_realm(context, principal)->data,
                                   "krbtgt",
                                   krb5_princ_realm(context, principal)->data,
                                   NULL);
    if (result) {
        state = Krb5TgtState_Invalid;
        error = QCoreApplication::translate("Krb5Client", "Failed to get valid TGT");
        throw(std::runtime_error(error.toUtf8().data()));
    }


    result = krb5_cc_retrieve_cred(context, ccache, 0, &creds, &creds);
    if (result) {
        state = Krb5TgtState_Invalid;
        throw(std::runtime_error(error.toUtf8().data()));
    }

    // Retrive lifetime and define TGT status...

}

Krb5Client::~Krb5Client() {
    krb5_free_cred_contents(context, &creds);
    krb5_free_principal(context, principal);
    krb5_cc_close(context, ccache);
    krb5_free_context(context);
}

void Krb5Client::authenticate(const QString &principal, const QString &password) {

}

void Krb5Client::refresh_tgt() {

}

Krb5TicketData Krb5Client::tgt_data() const {
    return tgt_contents;
}
