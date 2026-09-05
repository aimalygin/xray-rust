use serde_json::Value;

pub fn cases() -> Vec<Value> {
    let document: Value =
        serde_json::from_str(include_str!("../fixtures/config-tooling/cases.json")).unwrap();
    let cases = document["cases"].as_array().unwrap();
    cases
        .iter()
        .map(|case| {
            let mut case = case.clone();
            if let Some(base) = case["base"].as_str() {
                let mut config =
                    cases.iter().find(|entry| entry["name"] == base).unwrap()["config"].clone();
                for (pointer, value) in case["set"].as_object().unwrap() {
                    let (parent, key) = pointer.rsplit_once('/').unwrap();
                    let parent = config.pointer_mut(parent).unwrap();
                    if let Some(array) = parent.as_array_mut() {
                        array[key.parse::<usize>().unwrap()] = value.clone();
                    } else {
                        parent
                            .as_object_mut()
                            .unwrap()
                            .insert(key.replace("~1", "/").replace("~0", "~"), value.clone());
                    }
                }
                case["config"] = config;
            }
            case
        })
        .collect()
}
