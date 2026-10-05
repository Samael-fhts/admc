#ifndef USER_EDIT_H
#define USER_EDIT_H

#include <QWidget>

namespace Ui {
class UserResultsEditWidget;
}

class UserResultsEditWidget : public QWidget {
    Q_OBJECT

public:
    explicit UserResultsEditWidget(QWidget *parent = nullptr);
    ~UserResultsEditWidget();

private:
    Ui::UserResultsEditWidget *ui;
};

#endif // USER_EDIT_H
