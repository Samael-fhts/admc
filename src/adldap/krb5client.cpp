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

#include <QDateTime>

Krb5Client::Krb5Client() {

}

Krb5Client::~Krb5Client() {

}

void Krb5Client::authenticate(const QString &principal, const QString &password) {
    //    krb5_error_code result;
    //    krb5_context context;
    //    krb5_ccache ccache;

    //    result = krb5_init_context(&context);
    //    if (result) {
    //        show_error_message();
    //        return;
    //    }

    //    result = krb5_cc_default(context, &ccache);
    //    if (result == KRB5_CC_NOTFOUND) {
    //        show_error_message();
    //        return;
    //    }
}

void Krb5Client::refresh_tgt() {

}

Krb5TicketData Krb5Client::tgt_data() const {
    return tgt_contents;
}
