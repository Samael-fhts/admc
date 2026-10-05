#include "computer_edit.h"
#include "ui_computer_edit.h"

ComputerResultsEditWidget::ComputerResultsEditWidget(QWidget *parent)
: QWidget(parent)
, ui(new Ui::ComputerResultsEditWidget) {
    ui->setupUi(this);
}

ComputerResultsEditWidget::~ComputerResultsEditWidget() {
    delete ui;
}
