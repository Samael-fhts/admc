#ifndef COMPUTER_H
#define COMPUTER_H

#include "ui/widget/result/base.h"

class ComputerResultsEditWidget;

class ComputerResultsWidget final : public ResultsWidgetBase {
    Q_OBJECT

public:
    explicit ComputerResultsWidget(QWidget *parent = nullptr);
    ~ComputerResultsWidget() override;

    void update(AdInterface &ad, const AdObject &obj) override;

private:
    void on_apply() override;
    void on_edit() override;
    void on_cancel_edit() override;
    void set_editable(bool is_editable) override;
    QStringList changed_attrs() const override;

    ComputerResultsEditWidget *edit_wget;
};

#endif // COMPUTER_H
