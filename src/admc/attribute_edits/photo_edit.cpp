#include "photo_edit.h"
#include <QLabel>
#include <QPixmap>


PhotoEdit::PhotoEdit(QLabel *label, QObject *parent) : AttributeEdit(parent), photo_label(label) {

}

void PhotoEdit::load(AdInterface &ad, const AdObject &object) {

}

bool PhotoEdit::apply(AdInterface &ad, const QString &dn) const {

}


