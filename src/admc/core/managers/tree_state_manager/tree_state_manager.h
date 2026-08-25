/*
 * ADMC - AD Management Center
 *
 * Copyright (C) 2026 BaseALT Ltd.
 * Copyright (C) 2026 Semyon Knyazev
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef TREE_STATE_MANAGER_H
#define TREE_STATE_MANAGER_H

#include <QString>
#include <QPair>
#include "core/console_item_type.h"
#include <QQueue>
#include <QObject>
#include <QPersistentModelIndex>

class ConsoleWidget;
class QModelIndex;
class QTreeView;
class QAbstractItemModel;
class QAbstractProxyModel;

class TreeStateManager final : public QObject {
    using SelectedItemData = QPair<ItemType, QString>;

    Q_OBJECT

public:
    explicit TreeStateManager(ConsoleWidget *console, QTreeView *view,
        const QString &domain, const QString &user, QObject *parent);

    void set_context(const QString &domain, const QString &user);
    void save();
    void restore();

private slots:
    void on_rows_inserted(const QModelIndex &parent, int first, int last);

private:
    struct ExpandTask {
        QPersistentModelIndex root;
        QQueue<QString> dn_queue;
        int role = 0;
        ItemType item_type = ItemType_Unassigned;

        std::function<void()> on_finished;
    };

    ConsoleWidget *console_;
    QTreeView *view_;
    QString domain_;
    QString user_;
    QAbstractProxyModel *proxy_model_;
    QAbstractItemModel *source_model_;

    // Prefix and keys for tree state settings
    QString tree_state_prefix;
    const QString object_tree_key = "/objects";
    const QString policy_tree_key = "/policies";
    const QString policy_root_key = "/policy_root";
    const QString all_policies_folder_key = "/all_policies";
    const QString pso_tree_key = "/pso";
    const QString sites_tree_key = "/sites";
    const QString queries_tree_key = "/queries";
    const QString selected_item_key = "/selected_item";

    QQueue<ExpandTask> restore_task_queue_;
    bool restore_task_active_ = false;
    QPersistentModelIndex waiting_parent_;

    void enqueue_restore_task(const QModelIndex &root, const QStringList &name_list, int role,
        ItemType item_type, std::function<void()> on_finished = {});
    void start_next_restore_task();
    void continue_restore_task();
    void finish_current_restore_task();

    void save_object_subtree(const QModelIndex &parent, const QString &key);
    void save_policy_subtree();
    void save_pso_subtree();
    void save_query_subtree();

    QList<QModelIndex> expanded_index_list(const QModelIndex &parent);

    void save_current_selected_item();
    // Returns item type and DN (for AD objects) or item name
    // (for queries). For "All policies" folder, policy root
    // and query root returns only ItemType
    SelectedItemData selected_item_data();

    QQueue<QString> prepare_restore_dn_queue(const QString &base_dn, const QStringList &dn_list);

    void restore_object_subtree();
    void restore_policy_subtree();
    void restore_pso_subtree();
    void restore_sites_subtree();
    void restore_queries_subtree();

    void restore_current_selected_item();
    void restore_object_selection(const QString &dn);
};

#endif // TREE_STATE_MANAGER_H
