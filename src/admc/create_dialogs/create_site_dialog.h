#ifndef CREATE_SITE_DIALOG_H
#define CREATE_SITE_DIALOG_H

#include "create_object_dialog.h"

class CreateObjectHelper;
class AdInterface;

namespace Ui {
class CreateSiteDialog;
}

class CreateSiteDialog : public CreateObjectDialog {
    Q_OBJECT

public:
    explicit CreateSiteDialog(AdInterface &ad, QWidget *parent = nullptr);
    ~CreateSiteDialog();

    void accept() override;
    QString get_created_dn() const override;

private:
    Ui::CreateSiteDialog *ui;

    CreateObjectHelper *create_site_helper;
    CreateObjectHelper *create_ntds_settings_helper;
    CreateObjectHelper *create_servers_container_helper;
};

#endif // CREATE_SITE_DIALOG_H
