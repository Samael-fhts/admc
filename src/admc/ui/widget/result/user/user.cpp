#include "user.h"

UserResultsWidget::UserResultsWidget(QWidget *parent)
: ResultsWidgetBase(parent) {
}

UserResultsWidget::~UserResultsWidget() = default;

void UserResultsWidget::update(AdInterface &ad, const AdObject &obj) {
    ResultsWidgetBase::update(ad, obj);

    // User-specific update logic.
}

void UserResultsWidget::on_apply() {

    // User-specific apply logic.
}

void UserResultsWidget::on_edit() {
    ResultsWidgetBase::on_edit();

    // User-specific edit logic.
}

void UserResultsWidget::on_cancel_edit() {

    // User-specific cancel logic.
}

void UserResultsWidget::set_editable(bool is_editable) {
    ResultsWidgetBase::set_editable(is_editable);

    // User-specific editable state.
}

QStringList UserResultsWidget::changed_attrs() const {

    // Append user-specific attributes.

    return QStringList();
}
