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
#include <QDebug>
#include <unistd.h>
#include <sys/types.h>


Krb5Client::Krb5Client(bool use_default) : context(NULL), use_default_cache(use_default) {
    krb5_error_code res;

    res = krb5_init_context(&context);
    if (res) {
        const QString error = QCoreApplication::translate("Krb5Client", "Kerberos initialization failed");
        throw(std::runtime_error(error.toUtf8().data()));
    }

    load_caches();
}

Krb5Client::~Krb5Client() {
    krb5_free_context(context);
    for (krb5_ccache ccache : principal_cache_map.values()) {
        krb5_cc_close(context, ccache);
    }
}

void Krb5Client::authenticate(const QString &principal, const QString &password) {
    if (principal == curr_principal) {
        return;
    }

    kinit(principal, password);
    authenticate_with_cache(principal);
}

void Krb5Client::authenticate_with_cache(const QString &principal) {
    // Use ldap and gssapi here to connect with actual credentials ...
}

void Krb5Client::refresh_tgt(const QString &principal) {
    QString error = QCoreApplication::translate("Krb5Client", "Failed to refresh TGT");
    krb5_ccache ccache = principal_cache_map.value(principal, nullptr);
    if (!ccache) {
        throw_error(error, krb5_error_code);
    }

    krb5_creds new_creds;
    bool res = krb5_get_renewed_creds(context, &new_creds, principal, ccache, NULL) ||
            krb5_cc_store_cred(context, ccache, &new_creds);
    if (res) {
        krb5_free_cred_contents(context, &new_creds);
        throw_error(error, res);
    }
}

Krb5TGTData Krb5Client::tgt_data(const QString &principal) const {
    return principal_tgt_map[principal];
}

QString Krb5Client::current_principal() const {
    return curr_principal;
}

QString Krb5Client::default_principal() const {
    return def_principal;
}

bool Krb5Client::principal_has_cache(const QString &principal) const {
    return principal_cache_map.contains(principal);
}

void Krb5Client::set_default_cache_usage(bool use_default) {
    use_default_cache = use_default;
}

QStringList Krb5Client::available_principals() const {
    return principal_cache_map.keys();
}

void Krb5Client::kinit(const QString &principal, const QString &password) {
    krb5_creds creds;
    krb5_error_code res;
    QString error = QCoreApplication::translate("Krb5Client", "Authentication failed");

    const char *principal_name = principal.toUtf8().constData();
    krb5_principal princ;
    res = krb5_parse_name(context, principal_name, &princ);
    if (res) {
        throw_error(error, res);
    }

    memset(&creds, 0, sizeof(creds));
    const char *passwd = password.toUtf8().constData();
    res = krb5_get_init_creds_password(context, &creds, princ, passwd, NULL, NULL, 0, NULL, NULL);
    if (res) {
        cleanup_and_throw(error, res, nullptr, &creds, princ, nullptr);
    }

    krb5_ccache ccache;
    const uint uid = static_cast<uint>(getuid());
    const QString cache_name = QString("KEYRING:persistent:%1:krb5cc_%2").arg(QString::number(uid)).
                                                                              arg(principal);
    res = krb5_cc_resolve(context, cache_name.toUtf8().constData(), &ccache);
    if (res) {
        cleanup_and_throw(error, res, ccache, &creds, princ, nullptr);
    }

    res = krb5_cc_initialize(context, ccache, princ);
    if (res) {
        cleanup_and_throw(error, res, ccache, &creds, princ, nullptr);
    }

    res = krb5_cc_store_cred(context, ccache, &creds);
    if (res) {
        cleanup_and_throw(error, res, ccache, &creds, princ, nullptr);
    }

    // If there is no default principal switch to new ccache
    if (def_principal.isEmpty()) {
        res = krb5_cc_switch(context, ccache);
        res ? cleanup_and_throw(error, res, ccache, &creds, princ, nullptr) :
              load_cache_data(ccache, true);
        return;
    }

    load_cache_data(ccache, false);
    curr_principal = principal;
}

void Krb5Client::load_caches() {
    if (!krb5_cccol_have_content(context)) {
        qDebug() << "Failed to find any cache";
        return;
    }

    // Load default cache data
    krb5_ccache def_ccache = nullptr;
    krb5_error_code res = krb5_cc_default(context, &def_ccache);
    if (res) {
        qDebug() << "Failed to get default cache";
        krb5_cc_close(context, def_ccache);
        return;
    }
    load_cache_data(def_ccache, true);

    krb5_ccache ccache = nullptr;
    krb5_cccol_cursor cursor;
    res = krb5_cccol_cursor_new(context, &cursor);
    if (res) {
        qDebug() << "Failed to init krb cursor";
        return;
    }

    // Load other caches excluding default
    while (!krb5_cccol_cursor_next(context, cursor, &ccache)) {
        if (caches_are_equal(context, def_ccache, ccache)) {
            krb5_cc_close(context, ccache);
            continue;
        }

        load_cache_data(ccache, false);
        qDebug() << "Cache ptr: " << ccache;
    }

    krb5_cccol_cursor_free(context, &cursor);
}

void Krb5Client::load_cache_data(krb5_ccache ccache, bool is_default) {
    krb5_error_code res;
    krb5_principal principal;
    krb5_creds creds;
    Krb5TGTData tgt_data;

    res = krb5_cc_get_principal(context, ccache, &principal);
    if (res) {
        qDebug() << "Failed to get default principal";
        cleanup(ccache, nullptr, principal, nullptr);
        return;
    }

    char *princ = nullptr;
    res = krb5_unparse_name(context, principal, &princ);
    if (res) {
        cleanup(ccache, nullptr, principal, princ);
        return;
    }
    tgt_data.principal = princ;
    krb5_free_unparsed_name(context, princ);

    memset(&creds, 0, sizeof(creds));
    res = krb5_build_principal(context, &creds.server,
                                   krb5_princ_realm(context, principal)->length,
                                   krb5_princ_realm(context, principal)->data,
                                   "krbtgt",
                                   krb5_princ_realm(context, principal)->data,
                                   NULL);
    if (res) {
        qDebug() << "Failed to get server principal";
        cleanup(ccache, &creds, principal, nullptr);
        return;
    }

    res = krb5_cc_retrieve_cred(context, ccache, 0, &creds, &creds);
    if (res) {
        qDebug() << "Failed to retrieve creds";
        cleanup(ccache, &creds, principal, nullptr);
        return;
    }

    if (is_default) {
        def_principal = tgt_data.principal;
    }
    tgt_data.state = tgt_state_from_creds(creds);
    tgt_data.realm = principal->realm.data;
    tgt_data.starts.setSecsSinceEpoch(creds.times.starttime);
    tgt_data.renew_until.setSecsSinceEpoch(creds.times.renew_till);
    tgt_data.expires.setSecsSinceEpoch(creds.times.endtime);

    principal_tgt_map[tgt_data.principal] = tgt_data;
    principal_cache_map[tgt_data.principal] = ccache;

    qDebug() << "Tgt data retrieved_________ ";
    qDebug() << "Principal: " << tgt_data.principal;

    // ccache is not closed here  because it can be used later and will be
    // closed in destructor
    cleanup(nullptr, &creds, principal, nullptr);
}

Krb5TgtState Krb5Client::tgt_state_from_creds(const krb5_creds &creds) {
    std::time_t now = time(nullptr);
    if (now > creds.times.renew_till) {
        return Krb5TgtState_Outdated;
    }
    else if (now > creds.times.endtime) {
        return Krb5TgtState_Expired;
    }

    return Krb5TgtState_Active;
}

bool Krb5Client::caches_are_equal(krb5_context context, krb5_ccache cache1, krb5_ccache cache2) {
    krb5_principal p1, p2;
    if (krb5_cc_get_principal(context, cache1, &p1) || krb5_cc_get_principal(context, cache2, &p2)) {
        return false;
    }

    bool equal = krb5_principal_compare(context, p1, p2);
    krb5_free_principal(context, p1);
    krb5_free_principal(context, p2);
    return equal;
}

void Krb5Client::throw_error(const QString &error, krb5_error_code err_code) {
    QString out_err = err_code ? error + QString(': ') + krb5_get_error_message(context, err_code) :
                                 error;
    throw std::runtime_error(out_err.toUtf8().data());
}

void Krb5Client::cleanup(krb5_ccache ccache, krb5_creds *creds, krb5_principal principal, char *principal_unparsed) {
    if (ccache) {
        krb5_cc_close(context, ccache);
        ccache = nullptr;
    }

    if (creds) {
        krb5_free_cred_contents(context, creds);
        creds = nullptr;
    }

    if (principal) {
        krb5_free_principal(context, principal);
        principal = nullptr;
    }

    if (principal_unparsed) {
        krb5_free_unparsed_name(context, principal_unparsed);
        principal_unparsed = nullptr;
    }
}

void Krb5Client::cleanup_and_throw(const QString &error, krb5_error_code err_code, krb5_ccache ccache, krb5_creds *creds, krb5_principal principal, char *principal_unparsed) {
    cleanup(ccache, creds, principal, principal_unparsed);
    throw_error(error, err_code);
}
