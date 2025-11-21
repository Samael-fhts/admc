#ifndef CREATE_SUBNET_DIALOG_H
#define CREATE_SUBNET_DIALOG_H

#include "create_dialogs/create_object_dialog.h"

namespace Ui {
class CreateSubnetDialog;
}

class AdInterface;

class CreateSubnetDialog final : public CreateObjectDialog {
    Q_OBJECT

public:
    explicit CreateSubnetDialog(AdInterface &ad, const QString &parent_dn_arg, QWidget *parent = nullptr);
    ~CreateSubnetDialog();

    void accept() override;
    QString get_created_dn() const override;

private:
    Ui::CreateSubnetDialog *ui;
    QString parent_dn;
    QString created_dn;


    void check_prefix_validity(const QString &address);
    bool validate_ipv4_prefix(quint32 ip, int prefix);
    bool validate_ipv6_prefix(const quint8 ipv6[16], int prefix);
};

#endif // CREATE_SUBNET_DIALOG_H
