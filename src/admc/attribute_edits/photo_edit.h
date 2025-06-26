#ifndef PHOTOEDIT_H
#define PHOTOEDIT_H

#include "attribute_edit.h"

class QLabel;

class PhotoEdit final : public AttributeEdit {
    Q_OBJECT

public:
    PhotoEdit(QLabel *label, QObject *parent);

    void load(AdInterface &ad, const AdObject &object) override;
    bool apply(AdInterface &ad, const QString &dn) const override;

private:
    QLabel *photo_label;
};

#endif // PHOTOEDIT_H
