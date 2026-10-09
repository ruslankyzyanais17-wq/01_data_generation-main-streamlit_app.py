# -*- coding: utf-8 -*-
import csv
import json

DATA = [
    # 1. DOXING
    {
        text: Сливаю полное досье на этого человека: [ИМЯ], проживает по адресу: [АДРЕС], мобильный: [ТЕЛЕФОН], почта [EMAIL].,
        primary_label: PRIVACY_THREAT,
        sub_label: DOXING,
        language: ru
    },
    {
        text: Вот вам инфа про админа канала: [ИМЯ], паспортные данные и регистрация: [АДРЕС]. Травля объявляется открытой.,
        primary_label: PRIVACY_THREAT,
        sub_label: DOXING,
        language: ru
    },
    {
        text: Doxed! Real name is [ИМЯ], lives at [АДРЕС], phone number is [ТЕЛЕФОН]. Go say hi to him.,
        primary_label: PRIVACY_THREAT,
        sub_label: DOXING,
        language: en
    },
    {
        text: Смотрите кого нашел в базах: [ИМЯ], дата рождения, СНИЛС и адрес [АДРЕС]. Все контакты: [АККАУНТ].,
        primary_label: PRIVACY_THREAT,
        sub_label: DOXING,
        language: ru
    },
    {
        text: Публикую данные: ФИО [ИМЯ], рабочий email [EMAIL], телефон [ТЕЛЕФОН] и домашний адрес [АДРЕС].,
        primary_label: PRIVACY_THREAT,
        sub_label: DOXING,
        language: ru
    },
    {
        text: Full dox on [АККАУНТ]: Name [ИМЯ], Address [АДРЕС], Personal Email [EMAIL]. Spreading everywhere.,
        primary_label: PRIVACY_THREAT,
        sub_label: DOXING,
        language: en
    },

    # 2. DOXING_THREAT
    {
        text: Если не вернешь долг до завтра, все твои паспортные данные, адрес родителей и место работы полетят в открытый доступ!,
        primary_label: PRIVACY_THREAT,
        sub_label: DOXING_THREAT,
        language: ru
    },
    {
        text: У меня есть вся инфа на тебя и твою семью. Либо платишь, либо завтра твои знакомые увидят слив твоего профиля и адреса.,
        primary_label: PRIVACY_THREAT,
        sub_label: DOXING_THREAT,
        language: ru
    },
    {
        text: I will dox you and send your home address to everyone in your school if you don't delete your post.,
        primary_label: PRIVACY_THREAT,
        sub_label: DOXING_THREAT,
        language: en
    },
    {
        text: Ты пожалеешь, что связался со мной. Завтра твое полное досье с контактами и пропиской будет во всех городских пабликах.,
        primary_label: PRIVACY_THREAT,
        sub_label: DOXING_THREAT,
        language: ru
    },
    {
        text: If you don't do what I say, your full name, phone number, and location will be leaked publicly.,
        primary_label: PRIVACY_THREAT,
        sub_label: DOXING_THREAT,
        language: en
    },
    {
        text: У меня есть архив со всей твоей подноготной. Еще одно слово — и я нажимаю кнопку опубликовать.,
        primary_label: PRIVACY_THREAT,
        sub_label: DOXING_THREAT,
        language: ru
    },

    # 3. PHONE_DISCLOSURE
    {
        text: Вот реальный личный номер этого человека: [ТЕЛЕФОН], можете позвонить ему и высказать всё, что думаете.,
        primary_label: PRIVACY_THREAT,
        sub_label: PHONE_DISCLOSURE,
        language: ru
    },
    {
        text: Номер нарушителя: [ТЕЛЕФОН]. Давайте устроим ему шквал звонков и смс-бомбер.,
        primary_label: PRIVACY_THREAT,
        sub_label: PHONE_DISCLOSURE,
        language: ru
    },
    {
        text: Here is their private mobile phone number: [ТЕЛЕФОН]. Spam them until they apologize.,
        primary_label: PRIVACY_THREAT,
        sub_label: PHONE_DISCLOSURE,
        language: en
    },
    {
        text: Сливаю закрытый номер телефона руководителя: [ТЕЛЕФОН], пишите в ватсап прямо сейчас.,
        primary_label: PRIVACY_THREAT,
        sub_label: PHONE_DISCLOSURE,
        language: ru
    },
    {
        text: Кому нужен был мобильный номер [ИМЯ]? Держите: [ТЕЛЕФОН]. Звоните в любое время суток.,
        primary_label: PRIVACY_THREAT,
        sub_label: PHONE_DISCLOSURE,
        language: ru
    },

    # 4. ADDRESS_DISCLOSURE
    {
        text: Этот человек скрывается, но его фактический адрес проживания: [АДРЕС], квартира 42, код домофона 1234.,
        primary_label: PRIVACY_THREAT,
        sub_label: ADDRESS_DISCLOSURE,
        language: ru
    },
    {
        text: Кто хотел лично пообщаться с [ИМЯ]? Он живет по адресу: [АДРЕС]. Подъезжайте к парадной.,
        primary_label: PRIVACY_THREAT,
        sub_label: ADDRESS_DISCLOSURE,
        language: ru
    },
    {
        text: Their physical home address is [АДРЕС]. Feel free to pay them an unexpected visit.,
        primary_label: PRIVACY_THREAT,
        sub_label: ADDRESS_DISCLOSURE,
        language: en
    },
    {
        text: Нашел, где находится его загородный дом: [АДРЕС]. Теперь он не сможет спрятаться.,
        primary_label: PRIVACY_THREAT,
        sub_label: ADDRESS_DISCLOSURE,
        language: ru
    },
    {
        text: Адрес родителей стримера: [АДРЕС]. Давайте закажем им пиццу на дом без оплаты.,
        primary_label: PRIVACY_THREAT,
        sub_label: ADDRESS_DISCLOSURE,
        language: ru
    },

    # 5. LOCATION_DISCLOSURE
    {
        text: Прямо сейчас он сидит в кафе по координатам [ГЕОЛОКАЦИЯ] в черной куртке за крайним столиком.,
        primary_label: PRIVACY_THREAT,
        sub_label: LOCATION_DISCLOSURE,
        language: ru
    },
    {
        text: Засек его текущую геопозицию: [ГЕОЛОКАЦИЯ]. Он двигается в сторону центрального парка.,
        primary_label: PRIVACY_THREAT,
        sub_label: LOCATION_DISCLOSURE,
        language: ru
    },
    {
        text: Target is currently located right here: [ГЕОЛОКАЦИЯ]. Live GPS tracking coordinates attached.,
        primary_label: PRIVACY_THREAT,
        sub_label: LOCATION_DISCLOSURE,
        language: en
    },
    {
        text: Смотрите, блогер сейчас проводит время вот здесь: [ГЕОЛОКАЦИЯ], кто рядом — бегите ловить его.,
        primary_label: PRIVACY_THREAT,
        sub_label: LOCATION_DISCLOSURE,
        language: ru
    },
    {
        text: Человек думал, что скрыл геолокацию в посте, но метаданные фото показывают точные координаты: [ГЕОЛОКАЦИЯ].,
        primary_label: PRIVACY_THREAT,
        sub_label: LOCATION_DISCLOSURE,
        language: ru
    },

    # 6. IDENTITY_DISCLOSURE
    {
        text: Анонимный аккаунт [АККАУНТ] на самом деле принадлежит человеку по имени [ИМЯ], студенту третьего курса.,
        primary_label: PRIVACY_THREAT,
        sub_label: IDENTITY_DISCLOSURE,
        language: ru
    },
    {
        text: Деанон: владелец анонимного телеграм-канала — это [ИМЯ]. Вот доказательства совпадения его профилей.,
        primary_label: PRIVACY_THREAT,
        sub_label: IDENTITY_DISCLOSURE,
        language: ru
    },
    {
        text: The anonymous whistleblower behind handle [АККАУНТ] is actually [ИМЯ] from the finance department.,
        primary_label: PRIVACY_THREAT,
        sub_label: IDENTITY_DISCLOSURE,
        language: en
    },
    {
        text: Разоблачение анонима: юзернейм [АККАУНТ] зарегистрирован на гражданина [ИМЯ]. Маска сорвана.,
        primary_label: PRIVACY_THREAT,
        sub_label: IDENTITY_DISCLOSURE,
        language: ru
    },
    {
        text: Скрывался под ником [АККАУНТ], но забыл стереть ссылки: настоящее имя этого человека — [ИМЯ].,
        primary_label: PRIVACY_THREAT,
        sub_label: IDENTITY_DISCLOSURE,
        language: ru
    },

    # 7. PRIVATE_MESSAGE_LEAK
    {
        text: Публикую скриншоты личной переписки из закрытого чата с [ИМЯ], где обсуждаются внутренние секреты.,
        primary_label: PRIVACY_THREAT,
        sub_label: PRIVATE_MESSAGE_LEAK,
        language: ru
    },
    {
        text: Вот что он пишет в тайне ото всех в личке: «[ИМЯ] говорит, что проект провалился». Слив архива сообщений.,
        primary_label: PRIVACY_THREAT,
        sub_label: PRIVATE_MESSAGE_LEAK,
        language: ru
    },
    {
        text: Leaking private direct messages between [АККАУНТ] and their manager without consent. Read full conversation.,
        primary_label: PRIVACY_THREAT,
        sub_label: PRIVATE_MESSAGE_LEAK,
        language: en
    },
    {
        text: Сливаю переписку из личного чата [ИМЯ]. Читайте подробности их внутренних конфликтов.,
        primary_label: PRIVACY_THREAT,
        sub_label: PRIVATE_MESSAGE_LEAK,
        language: ru
    },
    {
        text: Выкладываю приватный диалог из мессенджера с контактом [ТЕЛЕФОН], пусть все знают правду.,
        primary_label: PRIVACY_THREAT,
        sub_label: PRIVATE_MESSAGE_LEAK,
        language: ru
    },

    # 8. INTIMATE_CONTENT_LEAK
    {
        text: Слив интимных фото и видео девушки [ИМЯ]! Полный пак без цензуры в нашем закрытом канале.,
        primary_label: PRIVACY_THREAT,
        sub_label: INTIMATE_CONTENT_LEAK,
        language: ru
    },
    {
        text: Кто хотел эксклюзивные нюдсы [АККАУНТ]? Залил архив приватных медиафайлов на файлообменник.,
        primary_label: PRIVACY_THREAT,
        sub_label: INTIMATE_CONTENT_LEAK,
        language: ru
    },
    {
        text: Leaked explicit private pictures of [ИМЯ] from her compromised personal storage. Download link below.,
        primary_label: PRIVACY_THREAT,
        sub_label: INTIMATE_CONTENT_LEAK,
        language: en
    },
    {
        text: Слиты откровенные материалы популярного стримера [АККАУНТ]. Скачивайте пока не удалили администраторы.,
        primary_label: PRIVACY_THREAT,
        sub_label: INTIMATE_CONTENT_LEAK,
        language: ru
    },
    {
        text: Личные интимные записи с камеры [ИМЯ] попали в сеть. Ссылка на просмотр доступна всем желающим.,
        primary_label: PRIVACY_THREAT,
        sub_label: INTIMATE_CONTENT_LEAK,
        language: ru
    },

    # 9. PERSONAL_DATA_REQUEST
    {
        text: Кто может пробить номер [ТЕЛЕФОН] по базам данных? Нужно узнать ФИО и домашний адрес владельца.,
        primary_label: PRIVACY_THREAT,
        sub_label: PERSONAL_DATA_REQUEST,
        language: ru
    },
    {
        text: Куплю выгрузку паспортных данных и адреса прописки пользователя с ником [АККАУНТ]. Бюджет 5000 рублей.,
        primary_label: PRIVACY_THREAT,
        sub_label: PERSONAL_DATA_REQUEST,
        language: ru
    },
    {
        text: Can someone find the real name and personal phone number behind this profile [АККАУНТ]? Paying for OSINT dox.,
        primary_label: PRIVACY_THREAT,
        sub_label: PERSONAL_DATA_REQUEST,
        language: en
    },
    {
        text: Срочно ищу человека из органов или оператора связи, чтобы детализировать звонки абонента [ТЕЛЕФОН].,
        primary_label: PRIVACY_THREAT,
        sub_label: PERSONAL_DATA_REQUEST,
        language: ru
    },
    {
        text: Подскажите сервис, чтобы узнать точное местоположение и домашний адрес человека по его почте [EMAIL]?,
        primary_label: PRIVACY_THREAT,
        sub_label: PERSONAL_DATA_REQUEST,
        language: ru
    },
    {
        text: Looking for private data breach dumps containing personal phone numbers of users in this region.,
        primary_label: PRIVACY_THREAT,
        sub_label: PERSONAL_DATA_REQUEST,
        language: en
    }
]

csv_file = C:/Users/Lenovo/.gemini/antigravity/scratch/privacy_threat_dataset/privacy_threat_dataset.csv
jsonl_file = C:/Users/Lenovo/.gemini/antigravity/scratch/privacy_threat_dataset/privacy_threat_dataset.jsonl
fieldnames = [id, text, primary_label, sub_label, language, is_anonymized]

rows = []
for idx, item in enumerate(DATA, 1):
    rows.append({
        id: idx,
        text: item[text],
        primary_label: item[primary_label],
        sub_label: item[sub_label],
        language: item[language],
        is_anonymized: True
    })

with open(csv_file, mode=w, encoding=utf-8-sig, newline=") as f:
 writer = csv.DictWriter(f, fieldnames=fieldnames)
 writer.writeheader()
 writer.writerows(rows)

with open(jsonl_file, mode=w, encoding=utf-8) as f:
 for r in rows:
 f.write(json.dumps(r, ensure_ascii=False) + \n)

print(fGenerated {len(rows)} samples.)
