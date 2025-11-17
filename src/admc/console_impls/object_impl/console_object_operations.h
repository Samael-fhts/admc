#ifndef OPERATIONS_H
#define OPERATIONS_H

#include "ad_defines.h"

class ConsoleWidget;
class QModelIndex;
class QString;
class AdInterface;
class AdObject;
class QStandardItem;
template<typename T> class QList;
template<typename K, typename V> class QHash;


namespace ConsoleObjectTreeOperations {
    void console_object_delete_dn_list(ConsoleWidget *console, const QList<QString> &dn_list, const QModelIndex &tree_root, const int type, const int dn_role);
    void console_object_move_and_rename(const QList<ConsoleWidget *> &console_list, AdInterface &ad, const QHash<QString, QString> &old_to_new_dn_map_arg, const QString &new_parent_dn);
    void add_objects_to_console(ConsoleWidget *console, const QList<AdObject> &object_list, const QModelIndex &parent);
    // Helper f-n that searches for objects and then adds them
    void object_impl_add_objects_to_console_from_dns(ConsoleWidget *console, AdInterface &ad, const QList<QString> &dn_list, const QModelIndex &parent);
    void console_object_load(const QList<QStandardItem *> row, const AdObject &object);
    void console_object_item_data_load(QStandardItem *item, const AdObject &object);
    void console_object_item_load_icon(QStandardItem *item, bool disabled);

    // NOTE: it is possible for a search to start while a
    // previous one hasn't finished. For that reason, this f-n
    // contains multiple workarounds for issues caused by that
    // case.
    void console_object_search(ConsoleWidget *console, const QModelIndex &index, const QString &base, const SearchScope scope, const QString &filter, const QList<QString> &attributes);
    QList<QString> object_impl_column_labels();
    QList<int> object_impl_default_columns();
    QList<QString> console_object_search_attributes();
    void console_object_tree_init(ConsoleWidget *console, AdInterface &ad);
    // NOTE: this may return an invalid index if there's no tree
    // of objects setup
    QModelIndex get_object_tree_root(ConsoleWidget *console);
    QString console_object_count_string(ConsoleWidget *console, const QModelIndex &index);
    void console_object_create(const QList<ConsoleWidget *> &console_list, const QString &object_class, const QString &parent_dn);
    void console_object_rename(const QList<ConsoleWidget *> &console_list, const QList<QModelIndex> &index_list, const int dn_role, const QString &object_class);
    void console_object_delete(const QList<ConsoleWidget *> &console_list, const QList<QModelIndex> &index_list, const int dn_role);
    void console_object_properties(const QList<ConsoleWidget *> &console_list, const QList<QModelIndex> &index_list, const int dn_role, const QList<QString> &class_list);
    bool console_object_deletion_dialog(ConsoleWidget *console, const QList<QModelIndex> &index_deleted_list);
    void console_tree_add_password_settings(ConsoleWidget *console, AdInterface &ad);
}

#endif // OPERATIONS_H
