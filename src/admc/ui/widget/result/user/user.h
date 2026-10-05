#ifndef USER_RESULTS_WIDGET_H
#define USER_RESULTS_WIDGET_H

#include "ui/widget/result/base.h"

class UserResultsEditWidget;

class UserResultsWidget final : public ResultsWidgetBase {
    Q_OBJECT

public:
    explicit UserResultsWidget(QWidget *parent = nullptr);
    ~UserResultsWidget() override;

    void update(AdInterface &ad, const AdObject &obj) override;

private:
    void on_apply() override;
    void on_edit() override;
    void on_cancel_edit() override;
    void set_editable(bool is_editable) override;
    QStringList changed_attrs() const override;

    UserResultsEditWidget *edit_wget;
};

#endif // USER_RESULTS_WIDGET_H
