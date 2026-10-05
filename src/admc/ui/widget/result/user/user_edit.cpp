#include "user_edit.h"
#include "ui_user_edit.h"

UserResultsEditWidget::UserResultsEditWidget(QWidget *parent)
: QWidget(parent)
, ui(new Ui::UserResultsEditWidget) {
    ui->setupUi(this);
}

UserResultsEditWidget::~UserResultsEditWidget() {
    delete ui;
}
