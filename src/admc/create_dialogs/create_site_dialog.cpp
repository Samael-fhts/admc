#include "create_site_dialog.h"
#include "ui_create_site_dialog.h"

#include "ad_interface.h"
#include "create_object_helper.h"
#include "globals.h"
#include "ad_config.h"
#include "ad_object.h"
#include "attribute_edits/site_links_table_edit.h"

CreateSiteDialog::CreateSiteDialog(AdInterface &ad, QWidget *parent) :
    CreateObjectDialog(parent),
    ui(new Ui::CreateSiteDialog) {
    ui->setupUi(this);

    SiteLinksTableEdit *edit = new SiteLinksTableEdit(ui->site_links_table, this);
    create_site_helper = new CreateObjectHelper(ui->name_edit, ui->buttonBox, {edit}, {}, CLASS_SITE,
                                    g_adconfig->sites_container_dn(), this);

    ui->site_links_table->setColumnCount(SiteLinksTableColumn_COUNT);
    ui->site_links_table->setHorizontalHeaderLabels({tr("Chain name"), tr("Transport")});
    ui->site_links_table->horizontalHeader()->resizeSections(QHeaderView::ResizeToContents);
    ui->site_links_table->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->site_links_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->site_links_table->selectRow(0);
    edit->load(ad, AdObject());
}

CreateSiteDialog::~CreateSiteDialog() {
    delete ui;
}

void CreateSiteDialog::accept() {
    const bool accepted = create_site_helper->accept();

    if (accepted) {
        QLineEdit *ntds_dummy_edit = new QLineEdit("NTDS Site Settings", this);
        QLineEdit *servers_dummy_edit = new QLineEdit("Servers", this);
        QDialogButtonBox *dummy_button_box = new QDialogButtonBox(QDialogButtonBox::Ok, this);
        servers_dummy_edit->hide();
        ntds_dummy_edit->hide();
        dummy_button_box->hide();

        create_ntds_settings_helper = new CreateObjectHelper(ntds_dummy_edit, dummy_button_box, {}, {}, CLASS_NTDS_SITE_SETTINGS,
                                                            get_created_dn(), this);
        create_servers_container_helper = new CreateObjectHelper(servers_dummy_edit, dummy_button_box, {}, {}, CLASS_SERVERS_CONTAINER,
                                                               get_created_dn(), this);

        if (create_ntds_settings_helper->accept() && create_servers_container_helper->accept()) {
            QDialog::accept();
        }
    }
}

QString CreateSiteDialog::get_created_dn() const {
    return create_site_helper->get_created_dn();
}
