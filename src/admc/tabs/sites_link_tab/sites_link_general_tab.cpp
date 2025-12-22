#include "sites_link_general_tab.h"
#include "ui_sites_link_general_tab.h"
#include "sites_link_widget.h"
#include "attribute_edits/sites_link_edit.h"
#include "attribute_edits/general_name_edit.h"

SitesLinkGeneralTab::SitesLinkGeneralTab(QList<AttributeEdit *> *edit_list, SitesLinkType type, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::SitesLinkGeneralTab),
    sites_link_widget(new SitesLinkWidget(type, this)) {

    ui->setupUi(this);

    edit_list->append(new GeneralNameEdit(ui->name_label, this));
    edit_list->append(new SitesLinkEdit(sites_link_widget, this));

    ui->verticalLayout->addWidget(sites_link_widget);
}

SitesLinkGeneralTab::~SitesLinkGeneralTab() {
    delete ui;
}
