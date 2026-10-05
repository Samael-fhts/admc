#include "group_edit.h"
#include "ui_group_edit.h"

GroupResultsEditWidget::GroupResultsEditWidget(QWidget *parent)
: QWidget(parent)
, ui(new Ui::GroupResultsEditWidget) {
    ui->setupUi(this);
}

GroupResultsEditWidget::~GroupResultsEditWidget() {
    delete ui;
}
