# NSZ to NSP Converter - Action Plan

## Goal
Сделать корректный AES-CTR decryption для NCZ секций, чтобы выходной NSP совпадал с референсом.

## Problem
Текущая реализация AES-CTR не давала правильный keystream. Нужно было понять, как PyCryptodome строит counter.

## ✅ Steps Completed

### 1. Изучена PyCryptodome реализация ✅
- Counter.new(64, prefix=nonce[0:8], initial_value=blockIndex)
- Counter block = nonce[0:8] + BE64(blockIndex)
- PyCryptodome использует big-endian для block index

### 2. Протестированы варианты counter format ✅
- BE64 (big-endian) в байтах 8-15 - ПРАВИЛЬНЫЙ вариант
- LE64 (little-endian) - не подходит

### 3. Исправлена реализация AES-CTR ✅
- Загружена библиотека `aes-js` (https://github.com/ricmoo/aes-js)
- `aesctr.js` теперь использует `aesjs.AES` для шифрования counter блока через AES-ECB
- Counter block строится как: nonce[0:8] + BE64(blockIndex)
- Исправлена обработка данных: шифруется counter через AES-ECB, затем результат XOR'ится с данными

### 4. Исправлена обработка BKTR секций ✅
- `AESCTR_BKTR` теперь работает так же, как `AESCTR` (использует правильный counter)
- Исправлено использование nonce (теперь используется весь 16-байтный counter из заголовка)

### 5. Исправлены вызовы в ncz.js ✅
- Удалено двойное добавление `UNCOMPRESSABLE_HEADER_SIZE` в `decryptSection`
- Исправлено использование `decryptSection` для всех типов секций
- Удалено условие `&& this.keys` которое блокировало дешифровку

## Files Modified
- `browser/crypto/aesctr.js` - Полностью переписан: использует aes-js, правильный counter (BE64)
- `browser/crypto/aes-js.js` - Загружен из GitHub (803 строки)
- `browser/index.html` - Добавлен `<script src="crypto/aes-js.js"></script>`
- `browser/ncz.js` - Исправлен `decryptSection`, удалено лишнее условие

## Remaining Tasks
1. Протестировать в браузере с реальным NSZ файлом
2. Сравнить SHA256 выходного файла с ожидаемым
3. Если не совпадает - отладить offset calculation

## Success Criteria
SHA256 выходного файла совпадает с `b46dffff5d030f22bb7cfd1e28459ab6fca52145f187b332e8a09e20279e7511`

## Test Files
- Input: `Super Chicken Jumper [01001DC018566000][v0] (0.05 GB).nsz`
- Reference: `Super Chicken Jumper [01001DC018566000][v0] (0.05 GB).nsp`
- Expected SHA256: `b46dffff5d030f22bb7cfd1e28459ab6fca52145f187b332e8a09e20279e7511`
