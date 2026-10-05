#ifndef COMPUTER_EDIT_H
#define COMPUTER_EDIT_H

#include <QWidget>

namespace Ui {
class ComputerResultsEditWidget;
}

class ComputerResultsEditWidget : public QWidget {
    Q_OBJECT

public:
    explicit ComputerResultsEditWidget(QWidget *parent = nullptr);
    ~ComputerResultsEditWidget();

private:
    Ui::ComputerResultsEditWidget *ui;
};

#endif // COMPUTER_EDIT_H
