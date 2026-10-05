#include "site_link.h"
#include "ui/widget/tab/sites_link/widget.h"
#include "../ui_base.h"
#include "ui/attribute_edit/sites_link_edit.h"
#include "ad_interface.h"
#include "ui/utils.h"
#include "ui/widget/tab/sites_link/part_widget.h"
#include "ui/attribute_edit/schedule_hours_edit.h"
#include <QSpacerItem>

SiteLinkResultsWidget::SiteLinkResultsWidget(QWidget *parent, SitesLinkType type) :
    ResultsWidgetBase(parent), sites_link_wget(new SitesLinkWidget(type, this)),
    sites_link_edit(new SitesLinkEdit(sites_link_wget, this)) {

    if (sites_link_wget->sites_link_part_widget()) {
        QPushButton *schedule_button = sites_link_wget->sites_link_part_widget()->schedule_button();
        schedule_hours_edit = new ScheduleHoursEdit(schedule_button, this);
    }

    ui->verticalLayout->addWidget(sites_link_wget);
    ui->verticalLayout->addStretch();
}

void SiteLinkResultsWidget::update(AdInterface &ad, const AdObject &obj) {
    saved_object = obj;
    set_editable(false);
    show_busy_indicator();
    sites_link_edit->load(ad, obj);
    if (schedule_hours_edit) {
        schedule_hours_edit->load(ad, obj);
    }
    hide_busy_indicator();
}

void SiteLinkResultsWidget::on_apply() {
    if (changed_attrs().isEmpty()) {
        set_editable(false);
        return;
    }

    show_busy_indicator();

    AdInterface ad;
    if (ad_failed(ad, this)) {
        hide_busy_indicator();
        on_cancel_edit();
        return;
    }

    if (!sites_link_edit->verify(ad, saved_object.get_dn())) {
        hide_busy_indicator();
        return;
    }

    sites_link_edit->apply(ad, saved_object.get_dn());
    if (schedule_hours_edit) {
        schedule_hours_edit->apply(ad, saved_object.get_dn());
    }

    saved_object = ad.search_object(saved_object.get_dn());

    hide_busy_indicator();

    set_editable(false);
}

void SiteLinkResultsWidget::on_edit() {
    set_editable(true);
}

void SiteLinkResultsWidget::on_cancel_edit() {
    sites_link_edit->update(saved_object);
    set_editable(false);
}

void SiteLinkResultsWidget::set_editable(bool is_editable) {
    ResultsWidgetBase::set_editable(is_editable);
    sites_link_wget->set_read_only(!is_editable);
}

QStringList SiteLinkResultsWidget::changed_attrs() const {
    QStringList changed_attr_list;
    QHash<QString, QList<QByteArray>> current_values_hash = sites_link_edit->get_values();
    for (const QString &attr : current_values_hash.keys()) {
        if (saved_object.get_values(attr) != current_values_hash[attr]) {
            changed_attr_list << attr;
        }
    }

    if (!schedule_hours_edit) {
        return changed_attr_list;
    }
    // TODO: add ScheduleHoursEdit to the SitesLinkEdit class
    // to not handle these edits separatly
    const QByteArray schedule_value = schedule_hours_edit->get_value();
    const QString schedule_attr = schedule_hours_edit->ad_attribute();
    if (!schedule_attr.isEmpty() &&
            saved_object.get_value(schedule_attr) != schedule_value) {
        changed_attr_list << schedule_attr;
    }

    return changed_attr_list;
}
