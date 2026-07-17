INSERT INTO `glpi_devicefirmwares` (`id`, `entities_id`, `is_recursive`, `name`, `version`, `date_mod`, `date_creation`) VALUES
(1, 0, 1, 'Cisco IOS-XE (Catalyst)', '17.09.04a', NOW(), NOW()),
(2, 0, 1, 'Cisco IOS-XE (ISR)', '17.06.05', NOW(), NOW()),
(3, 0, 1, 'Meraki AP Firmware', 'MR 29.6', NOW(), NOW());
INSERT INTO `glpi_items_devicefirmwares` (`entities_id`, `is_recursive`, `itemtype`, `items_id`, `devicefirmwares_id`, `date_mod`, `date_creation`) VALUES
-- Map Firmware 1 (IOS-XE 17.09) to SWITCH-MAIN (id: 1)
(0, 0, 'NetworkEquipment', 1, 1, NOW(), NOW()),

-- Map Firmware 2 (IOS-XE 17.06) to ROUTER-MAIN (id: 2)
(0, 0, 'NetworkEquipment', 2, 2, NOW(), NOW()),

-- Map Firmware 3 (MR 29.6) to AP-FLOOR1 (id: 3)
(0, 0, 'NetworkEquipment', 3, 3, NOW(), NOW()),

-- Map Firmware 3 (MR 29.6) to AP-FLOOR2 (id: 4)
(0, 0, 'NetworkEquipment', 4, 3, NOW(), NOW());
SELECT 
    net.`id` AS device_id,
    net.`name` AS device_name,
    net.`serial` AS serial_number,
    fw.`name` AS firmware,
    fw.`version` AS version
FROM `glpi_networkequipments` net
JOIN `glpi_items_devicefirmwares` link ON net.`id` = link.`items_id` AND link.`itemtype` = 'NetworkEquipment'
JOIN `glpi_devicefirmwares` fw ON link.`devicefirmwares_id` = fw.`id`
WHERE net.`id` IN (1, 2, 3, 4);