# Lua Proprietary Format Generator & Anti-Decompiler Security Suite

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![Lua 5.1](https://img.shields.io/badge/lua-5.1.5-blue.svg)](https://www.lua.org/)
[![Decompiler Protection](https://img.shields.io/badge/luadec-blocked-success.svg)](luadec)
[![Architecture](https://img.shields.io/badge/architecture-DDD%20%2F%20Hexagonal-blueviolet.svg)](gen_random_protocol)

**gen_lua_format** — генератор проприетарных бинарных форматов байткода для Lua на Python, построенный на архитектурных принципах **[gen_random_protocol](https://github.com/bivex/gen_random_protocol)** (Domain-Driven Design & Hexagonal Architecture).

Инструмент позволяет создавать кастомные, криптографически защищенные форматы байткода Lua, которые **невозможно разобрать стандартными декомпиляторами (например, `luadec`, `unluac`, `ChunkSpy`, `LAT`)**, при этом обеспечивая их полноценное исполнение как через нативный скомпилированный C VM Runner, так и через чистый Lua in-memory загрузчик (`loader.lua`).

---

## 📐 Архитектура (DDD & Hexagonal)

```text
               ┌────────────────────────────────────────────────────────┐
               │                  CLI / Presentation                    │
               │                   (gen_lua_format.py)                  │
               └───────────────────────────┬────────────────────────────┘
                                           │
                                           ▼
               ┌────────────────────────────────────────────────────────┐
               │                  Application Service                   │
               │        (lua_format/application/format_service.py)       │
               └───────────┬───────────────────────────────┬────────────┘
                           │                               │
                           ▼                               ▼
    ┌──────────────────────────────────────┐    ┌──────────────────────────────────────┐
    │             Domain Layer             │    │            Adapters Layer            │
    │  - LuaFormatGenerator (Seeded RNG)   │    │  - StandardLua51Reader / Writer      │
    │  - FormatProfile (Entity & Spec)     │    │  - ProprietaryLuaReader / Writer     │
    │  - 38 Lua 5.1 OpCode Matrix          │    │  - InstructionBitfieldCodec          │
    │  - Bitfield Layouts & XOR Transform  │    │  - 22-Byte Framing Envelope Codec    │
    │  - Constant Tag Remapping            │    │  - CRunnerEmitter (lua_runner.c)     │
    │  - Proto Section Reordering          │    │  - LuaLoaderEmitter (loader.lua)     │
    │  - 22B Wire Framing (from gen_proto) │    │  - MarkdownDocEmitter (RFC Spec)     │
    │  - HMAC-SHA256 Auth Trailer          │    │  - ManifestEmitter (JSON / YAML)     │
    └──────────────────────────────────────┘    └──────────────────────────────────────┘
```

---

## 🛡️ Уровни защиты от декомпиляции (`luadec` / `unluac`)

| Уровень защиты | Реализация | Эффект против декомпиляторов |
|---|---|---|
| **1. Кастомная сигнатура заголовка** | Замена `\x1bLua` на случайные или заданные байты (например, `\x7fU52`, `\x1bSEC`, `\x00PLU`). | `luadec` падает с ошибкой: `bad header in precompiled chunk` или `unexpected symbol`. |
| **2. Перестановка опкодов (0..37)** | Биективная перестановка всех 38 инструкций Lua 5.1 на основе сида (seed). | Если заголовок пропатчен, декомпилятор сопоставляет опкоды с неверной семантикой, вызывая crash / segfault / синтаксический мусор. |
| **3. Битфилд-трансформация инструкций** | Изменение позиций и битовых сдвигов полей (`OP_A_C_B`, `OP_A_B_C`, `A_OP_C_B`, `B_C_A_OP`, `C_B_A_OP`, `A_B_C_OP`). | Невозможно декодировать регистры A, B, C, Bx, sBx. |
| **4. Побитовая маска инструкций (XOR)** | Применение 32-битной псевдослучайной маски `ins ^ xor_mask`. | Инструкции превращаются в псевдослучайный шум. |
| **5. Перестановка тегов констант** | Перестановка ID типов (`TNIL`, `TBOOLEAN`, `TNUMBER`, `TSTRING`). | Таблица констант полностью искажается. |
| **6. Изменение порядка секций Proto** | Перестановка порядка записи секций в чанке (Code, Constants, Subprotos, Debug). | Десериализатор `luadec` читает числа как строки и падает с ошибкой EOF или bad integer. |
| **7. Обфускация строк** | XOR-маскирование тел строк и длин. | Строковые литералы не видны через `strings` и декомпиляторы. |
| **8. 22-байтовый сетевой конверт (Envelope)** | Оборачивание в канонический 22B заголовок из `gen_random_protocol` с CRC-32 и HMAC-SHA256. | Полная изоляция байткода на уровне протокола. |

---

## 🚀 Быстрый старт (CLI)

### 1. Автоматическая верификация устойчивости против `luadec`
Запуск полного цикла верификации (компиляция `.lua` -> проверка что `luadec` снимает обычный `.luac` -> шифрование в проприетарный `.luc` -> проверка что `luadec` **блокируется** -> исполнение через C Runner -> исполнение через Pure Loader -> декодирование):
```bash
python3 gen_lua_format.py verify
```

### 2. Генерация профиля проприетарного формата
```bash
# Генерация защищенного формата со спецификацией, C-раннером и Lua-лоадером
python3 gen_lua_format.py generate --seed a1b2c3d4e5f60718293a4b5c6d7e8f90 --name MY_SECURE_LUA -o out/my_format --build-runner
```
Команда создаст в `out/my_format/`:
- `LUA_FORMAT_SPEC.md` — детальная RFC-документация формата и матрица опкодов;
- `format_profile.yaml` / `format_manifest.json` — конфигурация профиля;
- `lua_custom_runner.c` — исходный код C раннера;
- `lua_runner` — скомпилированный нативный бинарник (если указан `--build-runner`);
- `loader.lua` — чистый Lua in-memory загрузчик.

### 3. Защита Lua скрипта (Encode)
```bash
python3 gen_lua_format.py protect myscript.lua -o out/my_format/myscript.luc --profile out/my_format/format_profile.yaml
```

### 4. Проверка того, что `luadec` не может декомпилировать
```bash
./luadec/luadec/luadec out/my_format/myscript.luc
# Вывод: luadec: out/my_format/myscript.luc:1: unexpected symbol near '...' (Exit code: 1)
```

### 5. Запуск проприетарного байткода
#### Способ А: Через нативный C Runner (максимальная скорость)
```bash
./out/my_format/lua_runner out/my_format/myscript.luc
```

#### Способ Б: Через чистый Lua In-Memory Loader (без перекомпиляции C)
```bash
./luadec/lua-5.1/src/lua out/my_format/loader.lua out/my_format/myscript.luc
```

#### Способ В: Подключение в существующий Lua проект
```lua
local loader = require("loader")
local protected_func = loader.loadfile("myscript.luc")
protected_func("arg1", "arg2")
```

### 6. Авторизованное декодирование (Decode)
```bash
python3 gen_lua_format.py unprotect out/my_format/myscript.luc -o out/my_format/recovered.luac --profile out/my_format/format_profile.yaml

# Восстановленный файл снова читается luadec:
./luadec/luadec/luadec out/my_format/recovered.luac
```

---

## 🧪 Запуск полного набора тестов

```bash
python3 -m unittest discover -s lua_format/tests
```

Все тесты проверяют:
- Корректность кодирования и декодирования всех 38 инструкций и всех типов констант;
- Round-trip сериализацию вложенных функций, замыканий (upvalues), таблиц и циклов;
- Полную блокировку стандартного декомпилятора `luadec`;
- Работоспособность и идентичность вывода C Runner и Pure Lua Loader.
