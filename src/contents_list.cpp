
#include "contents_list.h"
#include "ad_interface.h"
#include "ad_model.h"
#include "ad_filter.h"

#include <QApplication>
#include <QItemSelection>
#include <QSortFilterProxyModel>
#include <QMouseEvent>
#include <QDrag>
#include <QMimeData>
#include <QTreeView>

ContentsList::ContentsList(QTreeView *view, AdModel* model, QAction *advanced_view_toggle) :
QWidget(), 
proxy(model, advanced_view_toggle) 
{
    this->view = view;

    view->setModel(&proxy);
    view->hideColumn(AdModel::Column::DN);
};

// Both contents and containers share the same source model, but have different proxy's to it
// So need to map from containers proxy to source then back to proxy of contents
void ContentsList::set_root_index_from_selection(const QItemSelection &selected, const QItemSelection &) {

    const QList<QModelIndex> indexes = selected.indexes();

    if (indexes.size() == 0) {
        return;
    }

    // Map from proxy model of given index to source model of this view (if needed)
    QModelIndex source_index = indexes[0];
    {
        auto proxy_model = qobject_cast<const QSortFilterProxyModel *>(source_index.model());
        if (proxy_model != nullptr) {
            source_index = proxy_model->mapToSource(source_index);
        }
    }

    // Map from source model of this view to proxy model of this view (if needed)
    QModelIndex contents_index = source_index;
    {
        auto proxy_model = qobject_cast<const QSortFilterProxyModel *>(view->model());
        if (proxy_model != nullptr) {
            contents_index = proxy_model->mapFromSource(contents_index);
        }
    }

    if (!view->model()->checkIndex(contents_index)) {
        printf("ContentsList::set_root_index_from_selection received bad index!\n");
        return;
    }

    view->setRootIndex(contents_index);

    // NOTE: have to hide columns after model update
    view->hideColumn(AdModel::Column::DN);
}

// TODO: currently dragging doesn't work correctly most of the time
// the dragged item is not drawn (always the "X" icon)
// and on drag complete the item is not moved correctly
// icon is incorrect for example
// probably from dragging being started incorrectly
void ContentsList::mousePressEvent(QMouseEvent *event) {
    // view->mousePressEvent(event);

    // Record drag position
    if (event->button() == Qt::LeftButton) {
        drag_start_position = event->pos();
    }
}

void ContentsList::mouseMoveEvent(QMouseEvent *event) {
    // view->mouseMoveEvent(event);

    // Start drag event if holding left mouse button and dragged far enough

    bool holding_left_button = event->buttons() & Qt::LeftButton;
    if (!holding_left_button) {
        return;
    }

    int drag_distance = (event->pos() - drag_start_position).manhattanLength();
    if (drag_distance < QApplication::startDragDistance()) {
        return;
    }

    printf("drag start\n");

    QDrag *drag = new QDrag(this);

    // Figure out if this entry can be dragged
    // Entry has to be a person
    QPoint pos = event->pos();
    QModelIndex index = view->indexAt(pos);
    QModelIndex category_index = index.siblingAtColumn(AdModel::Column::Category);
    QString category_text = category_index.data().toString();

    if (category_text == "Person") {
        // Set drag data to the DN of clicked entry
        QModelIndex dn_index = index.siblingAtColumn(AdModel::Column::DN);
        QString dn = dn_index.data().toString();
        QMimeData *mime_data = new QMimeData();
        mime_data->setText(dn);
        drag->setMimeData(mime_data);

        drag->exec(Qt::MoveAction);
    }
}

void ContentsList::dragEnterEvent(QDragEnterEvent *event) {
    // view->dragEnterEvent(event);

    // TODO: is this needed?
    if (event->mimeData()->hasText()) {
        event->acceptProposedAction();
    }
}

bool can_drop_at() {
    // TODO: write this
    // not sure if to start from point or index
    return true;
}

void ContentsList::dragMoveEvent(QDragMoveEvent *event) {
    // Determine whether drag action is accepted at currently 
    // hovered entry
    // This only changes the drag icon

    // view->dragMoveEvent(event);

    QPoint pos = event->pos();
    QModelIndex index = view->indexAt(pos);
    QModelIndex category_index = index.siblingAtColumn(AdModel::Column::Category);
    QString category = category_index.data().toString();

    // TODO: currently using the shortened category
    // should use objectClass? so it needs to be cached alone or maybe all attributes need to be cached, whichever happens first 
    if (category == "Container" || category == "Organizational-Unit") {
        event->accept();
    } else {
        event->ignore();
    }
}

void ContentsList::dropEvent(QDropEvent *event) {
    // TODO: should accept? determining whether move succeeded is delayed until ad request is complete, so not sure how that works out
    // event->acceptProposedAction();

    printf("drop\n");

    QPoint pos = event->pos();
    QModelIndex target_index = view->indexAt(pos);
    QModelIndex target_category_index = target_index.siblingAtColumn(AdModel::Column::Category);
    QString target_category = target_category_index.data().toString();

    // TODO: figure out all possible move targets
    QList<QString> valid_move_target_categories = {
        "Container", "Organizational-Unit"
    };
    if (valid_move_target_categories.contains(target_category)) {
        QString user_dn = event->mimeData()->text();
        
        QModelIndex target_dn_index = target_index.siblingAtColumn(AdModel::Column::DN);
        QString target_dn = target_dn_index.data().toString();

        move_user(user_dn, target_dn);
        printf("dropped with valid target\n");
    } else {
        printf("dropped, but invalid target\n");
    }
}
