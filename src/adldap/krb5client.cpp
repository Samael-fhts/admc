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
#include <ctime>
#include <QSettings>


Krb5Client::Krb5Client() : context(NULL), ccache(NULL), principal(NULL), keytab(NULL) {
    krb5_error_code result;

    result = krb5_init_context(&context);
    if (result) {
        const QString error = QCoreApplication::translate("Krb5Client", "Kerberos initialization failed");
        throw(std::runtime_error(error.toUtf8().data()));
    }

    if (!setup_kerberos_cache()) {
        return;
    }

    result = krb5_cc_get_principal(context, ccache, &principal);
    if (result) {
        state = Krb5TgtState_Invalid;
        return;
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
        return;
    }

    result = krb5_cc_retrieve_cred(context, ccache, 0, &creds, &creds);
    if (result) {
        state = Krb5TgtState_Invalid;
        return;
    }

    std::time_t now = time(nullptr);
    if (now > creds.times.renew_till) {
        state = Krb5TgtState_Outdated;
    }
    else if (now > creds.times.endtime) {
        state = Krb5TgtState_Expired;
    }
    else {
        state = Krb5TgtState_Active;
    }

    fill_tgt_contents();
}

Krb5Client::~Krb5Client() {
    krb5_free_cred_contents(context, &creds);
    krb5_free_principal(context, principal);
    krb5_cc_close(context, ccache);
    krb5_free_context(context);
}

void Krb5Client::authenticate(const QString &principal, const QString &password) {
    const bool same_principal = principal == tgt_contents.principal;

    switch (state) {
    case Krb5TgtState_Active:
    case Krb5TgtState_Expired:
        same_principal ? refresh_tgt() : kinit(principal, password);
        break;
    case Krb5TgtState_Empty:
    case Krb5TgtState_Outdated:
        kinit(principal, password);
        break;
    case Krb5TgtState_Invalid:
    default:
        break;
    }
}

void Krb5Client::refresh_tgt() {
    QString error;
    krb5_creds new_creds;

    krb5_error res = krb5_get_renewed_creds(context, &new_creds, principal, ccache, NULL);
    if (res) {
        krb5_free_cred_contents(context, &new_creds);
        error = QCoreApplication::translate("Krb5Client", "Failed to refresh TGT");
        throw std::runtime_error(error.toUtf8().data());
    }

    krb5_free_cred_contents(context, &creds);
    res = krb5_copy_creds(context, &new_creds, &creds);
    if (res) {
        krb5_free_cred_contents(context, &new_creds);
        throw std::runtime_error(error.toUtf8().data());
    }

    res = krb5_cc_store_cred(context, ccache, &creds);
    if (res) {
        throw std::runtime_error(error.toUtf8().data());
    }
}

Krb5TicketData Krb5Client::tgt_data() const {
    return tgt_contents;
}

Krb5TgtState Krb5Client::tgt_state() const {
    return state;
}

void Krb5Client::kinit(const QString &principal, const QString &password) {

}

void Krb5Client::fill_tgt_contents() {
    tgt_contents.type = TicketType_TGT;

    char *principal_str = nullptr;
    krb5_error_code result = krb5_unparse_name(context, principal, &principal_str);
    if (result) {
        state = Krb5TgtState_Invalid;
        krb5_free_unparsed_name(context, principal_str);
        return;
    }
    tgt_contents.principal = principal_str;
    krb5_free_unparsed_name(context, principal_str);

    tgt_contents.realm = principal->realm.data;

    tgt_contents.starts.setSecsSinceEpoch(creds.times.starttime);
    tgt_contents.renew_until.setSecsSinceEpoch(creds.times.renew_till);
    tgt_contents.expires.setSecsSinceEpoch(creds.times.endtime);
}

bool Krb5Client::setup_kerberos_cache() {
    krb5_error result;
    result = krb5_cc_default(context, &ccache);
    if (result) {
        state = Krb5TgtState_Empty;
        return false;
    }

    return true;
}
