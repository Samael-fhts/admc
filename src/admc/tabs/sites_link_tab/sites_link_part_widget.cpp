#include "sites_link_part_widget.h"
#include "ui_sites_link_part_widget.h"

SitesLinkPartWidget::SitesLinkPartWidget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::SitesLinkPartWidget) {

    ui->setupUi(this);
}

SitesLinkPartWidget::~SitesLinkPartWidget() {
    delete ui;
}

QSpinBox *SitesLinkPartWidget::cost_spinbox() {
    return ui->cost_spbox;
}

QSpinBox *SitesLinkPartWidget::replicate_spinbox() {
    return ui->replicate_spbox;
}

QPushButton *SitesLinkPartWidget::schedule_button() {
    return ui->schedule_button;
}
