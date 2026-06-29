#ifndef SITE_LINK_RESULTS_WIDGET_H
#define SITE_LINK_RESULTS_WIDGET_H

#include "results_widgets/results_widget_base.h"
#include "tabs/sites_link_tab/sites_link_type.h"

class SitesLinkWidget;
class SitesLinkEdit;

class SiteLinkResultsWidget : public ResultsWidgetBase {

    Q_OBJECT

public:
    explicit SiteLinkResultsWidget(QWidget *parent, SitesLinkType type);
    virtual ~SiteLinkResultsWidget() = default;

    virtual void update(const AdObject &obj);

private:
    SitesLinkWidget *sites_link_wget = nullptr;
    SitesLinkEdit *sites_link_edit = nullptr;

    virtual void on_apply() override;
    virtual void on_edit() override;
    virtual void on_cancel_edit() override;
    virtual void set_editable(bool is_editable) override;
    virtual QStringList changed_attrs() const override;
};

#endif // SITE_LINK_RESULTS_WIDGET_H
