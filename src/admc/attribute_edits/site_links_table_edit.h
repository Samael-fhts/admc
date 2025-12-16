#ifndef SITELINKSTABLEEDIT_H
#define SITELINKSTABLEEDIT_H

#include "attribute_edit.h"

class QTableWidget;

enum SiteLinksTableColumn {
    SiteLinksTableColumn_ChainName,
    SiteLinksTableColumn_Transport,

    SiteLinksTableColumn_COUNT
};

class SiteLinksTableEdit final : public AttributeEdit {
    Q_OBJECT

public:
    SiteLinksTableEdit(QTableWidget *site_links_table_arg, QObject *parent);

    void load(AdInterface &ad, const AdObject &object) override;
    bool apply(AdInterface &ad, const QString &dn) const override;

private:
    QTableWidget *site_links_table;

    bool site_exists(AdInterface &ad, const QString &site_dn) const;
};

#endif // SITELINKSTABLEEDIT_H
