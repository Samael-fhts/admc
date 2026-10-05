#ifndef GROUP_H
#define GROUP_H

#include "ui/widget/result/base.h"

class GroupResultsEditWidget;

class GroupResultsWidget final : public ResultsWidgetBase {
    Q_OBJECT

public:
    explicit GroupResultsWidget(QWidget *parent = nullptr);
    ~GroupResultsWidget() override;

    void update(AdInterface &ad, const AdObject &obj) override;

private:
    void on_apply() override;
    void on_edit() override;
    void on_cancel_edit() override;
    void set_editable(bool is_editable) override;
    QStringList changed_attrs() const override;

    GroupResultsEditWidget *edit_wget;
};

#endif // GROUP_H
