/*
 * ADMC - AD Management Center
 *
 * Copyright (C) 2020 BaseALT Ltd.
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

#include "edits/upn_suffix_widget.h"

#include "adldap.h"
#include "globals.h"

#include <QComboBox>
#include <QVBoxLayout>

UpnSuffixWidget::UpnSuffixWidget(AdInterface &ad)
: QWidget()
{
    combo = new QComboBox();

    const QList<QString> suffixes =
    [&]() {
        QList<QString> out;

        const QString partitions_dn = g_adconfig->partitions_dn();
        const AdObject partitions_object = ad.search_object(partitions_dn);

        out = partitions_object.get_strings(ATTRIBUTE_UPN_SUFFIXES);

        const QString domain = g_adconfig->domain();
        const QString domain_suffix = domain.toLower();
        if (!out.contains(domain_suffix)) {
            out.append(domain_suffix);
        }

        return out;
    }();

    for (const QString &suffix : suffixes) {
        combo->addItem(suffix);
    }

    auto layout = new QVBoxLayout();
    setLayout(layout);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    layout->addWidget(combo);

    QObject::connect(
        combo, &QComboBox::currentTextChanged,
        this, &UpnSuffixWidget::edited);
}

QString UpnSuffixWidget::get_suffix() const {
    return combo->currentText();
}

void UpnSuffixWidget::load(const AdObject &object) {
    const QString suffix = object.get_upn_suffix();

    // Select current suffix in suffix combo. Add current
    // suffix to combo if it's not there already.
    const int suffix_index = combo->findText(suffix);
    if (suffix_index != -1) {
        combo->setCurrentIndex(suffix_index);
    } else {
        combo->addItem(suffix);
        
        const int added_index = combo->findText(suffix);
        combo->setCurrentIndex(added_index);
    }
}

void UpnSuffixWidget::set_enabled(const bool enabled) {
    combo->setEnabled(enabled);
}
