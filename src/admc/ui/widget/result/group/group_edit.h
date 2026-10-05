#ifndef GROUP_EDIT_H
#define GROUP_EDIT_H

#include <QWidget>

namespace Ui {
class GroupResultsEditWidget;
}

class GroupResultsEditWidget : public QWidget {
    Q_OBJECT

public:
    explicit GroupResultsEditWidget(QWidget *parent = nullptr);
    ~GroupResultsEditWidget();

private:
    Ui::GroupResultsEditWidget *ui;
};

#endif // GROUP_EDIT_H
