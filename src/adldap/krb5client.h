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

enum TicketType {
    TicketType_TGT,
    TicketType_Service
};

struct Krb5TicketData {
    QString principal;
    QString realm;
    QDateTime starts;
    QDateTime expires;
    QDateTime renew_until;
    TicketType type;
};

enum Krb5TgtState {
    Krb5TgtState_Empty, // Cache is invalid or has no tickets
    Krb5TgtState_Active, // Ticket (TGT) is valid and a up-to-date
    Krb5TgtState_Expired, // TGT is expired, but can be refreshed
    Krb5TgtState_Outdated, // TGT lifetime is out of date and can't be refreshed
    Krb5TgtState_Invalid // TGT is not valid for some reason
};

class Krb5Client {
public:
    Krb5Client();
    ~Krb5Client();

    void authenticate(const QString &principal, const QString &password);
    void refresh_tgt();
    Krb5TicketData tgt_data() const;
    Krb5TgtState tgt_state() const;
    void get_tgt_with_keytab();
    bool keytab_is_available() const;

private:
    Krb5TgtState state;
    krb5_context context;
    krb5_ccache ccache;
    krb5_principal principal;
    krb5_creds creds;
    Krb5TicketData tgt_contents;
    krb5_keytab keytab;

    void kinit(const QString &principal, const QString &password);
    void fill_tgt_contents();
};

#endif // KRB5CLIENT_H
