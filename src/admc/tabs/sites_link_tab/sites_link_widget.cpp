#include "sites_link_widget.h"
#include "ui_sites_link_widget.h"
#include "sites_link_part_widget.h"
#include <QLabel>

SitesLinkWidget::SitesLinkWidget(SitesLinkType type_arg, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::SitesLinkWidget),
    type(type_arg) {

    ui->setupUi(this);

    common_wget = ui->sites_link_common_wget;
    common_wget->set_lists_labels(type);

    if (type_arg == SitesLinkType::Link) {
        sites_link_part_wget = new SitesLinkPartWidget(this);
        ui->verticalLayout->addWidget(sites_link_part_wget);
    }
}

SitesLinkWidget::~SitesLinkWidget() {
    delete ui;
}

SitesLinkCommonWidget *SitesLinkWidget::common_widget() {
    return common_wget;
}

SitesLinkPartWidget *SitesLinkWidget::sites_link_part_widget() {
    return sites_link_part_wget;
}

SitesLinkType SitesLinkWidget::get_type() {
    return type;
}




