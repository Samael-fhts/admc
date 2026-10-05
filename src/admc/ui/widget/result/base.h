#ifndef RESULTS_WIDGET_BASE_H
#define RESULTS_WIDGET_BASE_H

#include <QWidget>
#include "ad_object.h"

namespace Ui {
class ResultsWidgetBase;
}

class AdInterface;

class ResultsWidgetBase : public QWidget {
    Q_OBJECT

public:
    explicit ResultsWidgetBase(QWidget *parent = nullptr);
    virtual ~ResultsWidgetBase();

    virtual void update(AdInterface &ad, const AdObject &obj);

    void retranslate_ui();
    bool event(QEvent *event);

protected:
    Ui::ResultsWidgetBase *ui;
    AdObject saved_object;

    virtual void on_apply();
    virtual void on_edit();
    virtual void on_cancel_edit();
    virtual void set_editable(bool is_editable);
    virtual QStringList changed_attrs() const;
};

#endif // RESULTS_WIDGET_BASE_H
