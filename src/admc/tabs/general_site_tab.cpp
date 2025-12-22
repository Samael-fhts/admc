#include "general_site_tab.h"
#include "ui_general_site_tab.h"

#include "attribute_edits/general_name_edit.h"
#include "attribute_edits/string_edit.h"
#include "attribute_edits/subnets_list_edit.h"
#include "ad_defines.h"


GeneralSiteTab::GeneralSiteTab(QList<AttributeEdit *> *edit_list, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::GeneralSiteTab) {
    ui->setupUi(this);

    auto name_edit = new GeneralNameEdit(ui->name_label, this);
    auto description_edit = new StringEdit(ui->description_edit, ATTRIBUTE_DESCRIPTION, this);
    auto subnets_list_edit = new SubnetsListEdit(ui->subnets_list_widget, this);

    edit_list->append({
        name_edit,
        description_edit,
        subnets_list_edit
    });
}

GeneralSiteTab::~GeneralSiteTab() {
    delete ui;
}
