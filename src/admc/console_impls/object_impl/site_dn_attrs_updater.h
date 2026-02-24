#ifndef SITEDNATTRSUPDATER_H
#define SITEDNATTRSUPDATER_H

#include <QString>

class AdInterface;

// 1. Update site links
// 2. Fix attr ms-DS-NC-Replica-Locations in the crossrefs for
//    DomainDnsZones and ForestDnsZones
// 3. Update dnsNode objects names (dns records)
class SiteDnAttrsUpdater {
public:
    explicit SiteDnAttrsUpdater(const QString &site_dn);

    void update_for_delete(AdInterface &ad);
    void update_for_rename(AdInterface &ad, const QString &new_dn);

private:
    QString dn;

    void update_site_links(AdInterface &ad, const QString &new_site_dn);
    void update_dns_records(AdInterface &ad, const QString &new_site_dn);
};

#endif // SITEDNATTRSUPDATER_H
