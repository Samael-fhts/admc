#include "site_link_results_widget.h"
#include "tabs/sites_link_tab/sites_link_widget.h"
#include "attribute_edits/sites_link_edit.h"
#include "ad_interface.h"
#include "utils.h"

SiteLinkResultsWidget::SiteLinkResultsWidget(QWidget *parent, SitesLinkType type) :
    ResultsWidgetBase(parent), sites_link_wget(new SitesLinkWidget(type, this)),
    sites_link_edit(new SitesLinkEdit(sites_link_wget, this)) {

}

void SiteLinkResultsWidget::update(const AdObject &obj) {
    AdInterface ad;
    if (ad_failed(ad, this)) {
        return;
    }

    saved_object = obj;

    show_busy_indicator();
    sites_link_edit->load(ad, obj);
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
        on_cancel_edit();
        return;
    }

    if (!sites_link_edit->verify(ad, saved_object.get_dn())) {
        return;
    }

    sites_link_edit->apply(ad, saved_object.get_dn());
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
    sites_link_wget->setDisabled(!is_editable);
}

QStringList SiteLinkResultsWidget::changed_attrs() const {
    QStringList changed_attr_list;
    QHash<QString, QList<QByteArray>> current_values_hash = sites_link_edit->get_values();
    for (const QString &attr : current_values_hash.keys()) {
        if (saved_object.get_values(attr) != current_values_hash[attr]) {
            changed_attr_list << attr;
        }
    }

    return changed_attr_list;
}
