#include "computer.h"

ComputerResultsWidget::ComputerResultsWidget(QWidget *parent)
: ResultsWidgetBase(parent) {
}

ComputerResultsWidget::~ComputerResultsWidget() = default;

void ComputerResultsWidget::update(AdInterface &ad, const AdObject &obj) {
    ResultsWidgetBase::update(ad, obj);

    // Computer-specific update logic.
}

void ComputerResultsWidget::on_apply() {
    ResultsWidgetBase::on_apply();

    // Computer-specific apply logic.
}

void ComputerResultsWidget::on_edit() {
    ResultsWidgetBase::on_edit();

    // Computer-specific edit logic.
}

void ComputerResultsWidget::on_cancel_edit() {
    ResultsWidgetBase::on_cancel_edit();

    // Computer-specific cancel logic.
}

void ComputerResultsWidget::set_editable(bool is_editable) {
    ResultsWidgetBase::set_editable(is_editable);

    // Computer-specific editable state.
}

QStringList ComputerResultsWidget::changed_attrs() const {
    QStringList attrs = ResultsWidgetBase::changed_attrs();

    // Append computer-specific attributes.

    return attrs;
}
