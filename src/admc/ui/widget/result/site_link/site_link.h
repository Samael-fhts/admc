#ifndef SITE_LINK_RESULTS_WIDGET_H
#define SITE_LINK_RESULTS_WIDGET_H

#include "ui/widget/result/base.h"
#include "ui/widget/tab/sites_link/type.h"

class SitesLinkWidget;
class SitesLinkEdit;
class ScheduleHoursEdit;

class SiteLinkResultsWidget : public ResultsWidgetBase {

    Q_OBJECT

public:
    explicit SiteLinkResultsWidget(QWidget *parent, SitesLinkType type);
    virtual ~SiteLinkResultsWidget() = default;

    virtual void update(AdInterface &ad, const AdObject &obj);

private:
    SitesLinkWidget *sites_link_wget = nullptr;
    SitesLinkEdit *sites_link_edit = nullptr;
    ScheduleHoursEdit *schedule_hours_edit = nullptr;

    void on_apply() override;
    void on_edit() override;
    void on_cancel_edit() override;
    void set_editable(bool is_editable) override;
    QStringList changed_attrs() const override;
};

#endif // SITE_LINK_RESULTS_WIDGET_H
