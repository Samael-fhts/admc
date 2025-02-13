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

#ifndef KRB5CLIENT_H
#define KRB5CLIENT_H

#include <krb5.h>
#include <QDateTime>
#include <QHash>


enum Krb5TgtState {
    Krb5TgtState_Empty, // Cache is invalid or has no tickets
    Krb5TgtState_Active, // Ticket (TGT) is valid and a up-to-date
    Krb5TgtState_Expired, // TGT is expired, but can be refreshed
    Krb5TgtState_Outdated, // TGT lifetime is out of date and can't be refreshed
    Krb5TgtState_Invalid // TGT is not valid for some reason
};

struct Krb5TGTData {
    Krb5TgtState state = Krb5TgtState_Invalid;
    QString principal;
    QString realm;
    QDateTime starts;
    QDateTime expires;
    QDateTime renew_until;
};

inline const QString use_default_cache_setting = "SETTING_use_default_credentials";

class Krb5Client {
public:
    Krb5Client();
    ~Krb5Client();

    void authenticate(const QString &principal, const QString &password);
    void authenticate_with_cache(const QString &principal);
    void refresh_tgt(const QString &principal);
    Krb5TGTData tgt_data(const QString &principal) const;
    QString default_principal() const; // Returns principal contained in the system credential cache
    QString current_principal() const; // Returns last authenticated principal
    bool principal_has_cache(const QString &principal) const;

private:
    krb5_context context;
    QString curr_principal;
    QString def_principal;
    QHash<QString, Krb5TGTData> principal_tgt_map;
    QHash<QString, krb5_ccache> principal_cache_map;

    void kinit(const QString &principal, const QString &password);
    void load_default_cache();
    void load_custom_caches();
};

#endif // KRB5CLIENT_H
